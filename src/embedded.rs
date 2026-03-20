use crate::bus::EventBus;
use crate::config::EmbeddedConfig;
use crate::event::{Event, EventKind, Severity};
use crate::shutdown::ShutdownListener;
use crate::storage::Storage;
use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::fs;

static EMBEDDED_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn spawn_embedded_collectors(
    bus: EventBus,
    storage: Storage,
    config: EmbeddedConfig,
    shutdown: ShutdownListener,
) {
    tokio::spawn(async move {
        run_embedded_collectors(bus, storage, config, shutdown).await;
    });
}

async fn run_embedded_collectors(
    bus: EventBus,
    storage: Storage,
    config: EmbeddedConfig,
    mut shutdown: ShutdownListener,
) {
    if !config.enabled {
        tracing::info!("embedded collectors disabled");
        return;
    }
    if std::env::consts::OS != "linux" {
        tracing::info!("embedded collectors only supported on linux");
        return;
    }

    let jetson = if config.jetson_enabled {
        discover_jetson_paths().await
    } else {
        None
    };

    let mut state = CollectorState::new(config, jetson);
    let mut interval = tokio::time::interval(Duration::from_millis(state.config.interval_ms));

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::info!("embedded collectors shutting down");
                break;
            }
            _ = interval.tick() => {
                state.collect(&bus, &storage).await;
            }
        }
    }
}

struct CollectorState {
    config: EmbeddedConfig,
    prev_cpu: Option<CpuTotals>,
    mem_total_bytes: Option<u64>,
    prev_disk: HashMap<String, IoTotals>,
    prev_net: HashMap<String, NetTotals>,
    max_disk_rate: HashMap<String, f64>,
    max_net_rate: HashMap<String, f64>,
    proc_prev: HashMap<u32, ProcSample>,
    proc_prev_total: Option<u64>,
    proc_last: Instant,
    proc_io_max: HashMap<String, f64>,
    jetson: Option<JetsonPaths>,
    last_sample: Instant,
}

impl CollectorState {
    fn new(config: EmbeddedConfig, jetson: Option<JetsonPaths>) -> Self {
        Self {
            config,
            prev_cpu: None,
            mem_total_bytes: None,
            prev_disk: HashMap::new(),
            prev_net: HashMap::new(),
            max_disk_rate: HashMap::new(),
            max_net_rate: HashMap::new(),
            proc_prev: HashMap::new(),
            proc_prev_total: None,
            proc_last: Instant::now(),
            proc_io_max: HashMap::new(),
            jetson,
            last_sample: Instant::now(),
        }
    }

    async fn collect(&mut self, bus: &EventBus, storage: &Storage) {
        let elapsed = self.last_sample.elapsed().as_secs_f64().max(0.001);
        self.last_sample = Instant::now();

        if let Some(cpu) = read_cpu().await {
            if let Some(prev) = self.prev_cpu {
                let total_delta = cpu.total.saturating_sub(prev.total) as f64;
                let idle_delta = cpu.idle.saturating_sub(prev.idle) as f64;
                if total_delta > 0.0 {
                    let usage = ((total_delta - idle_delta) / total_delta).clamp(0.0, 1.0);
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "cpu_usage",
                        usage * 100.0,
                        "percent",
                        usage,
                        severity_from_ratio(usage),
                        &[],
                    )
                    .await;
                }
            }
            self.prev_cpu = Some(cpu);
        }

        if let Some(mem) = read_meminfo().await {
            if let (Some(total), Some(available)) = (mem.total_kb, mem.available_kb) {
                let used_kb = total.saturating_sub(available);
                let usage = (used_kb as f64 / total as f64).clamp(0.0, 1.0);
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "mem_used",
                    used_kb as f64 * 1024.0,
                    "bytes",
                    usage,
                    severity_from_ratio(usage),
                    &[],
                )
                .await;
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "mem_available",
                    available as f64 * 1024.0,
                    "bytes",
                    1.0 - usage,
                    Severity::Low,
                    &[],
                )
                .await;
            }
            self.mem_total_bytes = mem.total_kb.map(|v| v.saturating_mul(1024));
            if let (Some(total), Some(free)) = (mem.swap_total_kb, mem.swap_free_kb) {
                if total > 0 {
                    let used_kb = total.saturating_sub(free);
                    let usage = (used_kb as f64 / total as f64).clamp(0.0, 1.0);
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "swap_used",
                        used_kb as f64 * 1024.0,
                        "bytes",
                        usage,
                        severity_from_ratio(usage),
                        &[],
                    )
                    .await;
                }
            }
        }

        let thermals = read_thermals().await;
        for thermal in thermals.into_iter().take(self.config.max_thermals) {
            let ratio = (thermal.temp_c / 100.0).clamp(0.0, 1.0);
            emit_metric(
                bus,
                storage,
                "embedded",
                "thermal_temp",
                thermal.temp_c,
                "celsius",
                ratio,
                severity_from_ratio(ratio),
                &[("zone", thermal.zone), ("type", thermal.sensor_type)],
            )
            .await;
        }

        if let Some(disks) = read_disks().await {
            for disk in disks.into_iter().take(self.config.max_disks) {
                let prev = self.prev_disk.get(&disk.name).cloned();
                if let Some(prev) = prev {
                    let read_rate = rate_bytes(disk.read_bytes, prev.read_bytes, elapsed);
                    let write_rate = rate_bytes(disk.write_bytes, prev.write_bytes, elapsed);
                    let read_ratio = track_rate(
                        &mut self.max_disk_rate,
                        &format!("{}:read", disk.name),
                        read_rate,
                    );
                    let write_ratio = track_rate(
                        &mut self.max_disk_rate,
                        &format!("{}:write", disk.name),
                        write_rate,
                    );
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "disk_read_bps",
                        read_rate,
                        "bytes_per_sec",
                        read_ratio,
                        Severity::Low,
                        &[("device", disk.name.clone())],
                    )
                    .await;
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "disk_write_bps",
                        write_rate,
                        "bytes_per_sec",
                        write_ratio,
                        Severity::Low,
                        &[("device", disk.name.clone())],
                    )
                    .await;
                }
                self.prev_disk.insert(disk.name.clone(), disk.totals());
            }
        }

        if let Some(nets) = read_net().await {
            for net in nets.into_iter().take(self.config.max_interfaces) {
                let prev = self.prev_net.get(&net.iface).cloned();
                if let Some(prev) = prev {
                    let rx_rate = rate_bytes(net.rx_bytes, prev.rx_bytes, elapsed);
                    let tx_rate = rate_bytes(net.tx_bytes, prev.tx_bytes, elapsed);
                    let rx_ratio = track_rate(
                        &mut self.max_net_rate,
                        &format!("{}:rx", net.iface),
                        rx_rate,
                    );
                    let tx_ratio = track_rate(
                        &mut self.max_net_rate,
                        &format!("{}:tx", net.iface),
                        tx_rate,
                    );
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "net_rx_bps",
                        rx_rate,
                        "bytes_per_sec",
                        rx_ratio,
                        Severity::Low,
                        &[("iface", net.iface.clone())],
                    )
                    .await;
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "net_tx_bps",
                        tx_rate,
                        "bytes_per_sec",
                        tx_ratio,
                        Severity::Low,
                        &[("iface", net.iface.clone())],
                    )
                    .await;
                }
                self.prev_net.insert(net.iface.clone(), net.totals());
            }
        }

        self.collect_disk_usage(bus, storage).await;
        self.collect_battery(bus, storage).await;
        self.collect_processes(bus, storage).await;
        self.collect_gpus(bus, storage).await;

        if let Some(jetson) = &self.jetson {
            if let Some(load) = read_u64_opt(&jetson.gpu_load).await {
                let scale = if load > 1000 { 1000.0 } else { 100.0 };
                let ratio = ((load as f64) / scale).clamp(0.0, 1.0);
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "jetson_gpu_load",
                    ratio * 100.0,
                    "percent",
                    ratio,
                    severity_from_ratio(ratio),
                    &[],
                )
                .await;
            }
            if let Some(freq) = read_u64_opt(&jetson.gpu_freq).await {
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "jetson_gpu_freq",
                    freq as f64,
                    "hz",
                    0.0,
                    Severity::Low,
                    &[],
                )
                .await;
            }
            if let Some(path) = &jetson.fan_rpm {
                if let Some(rpm) = read_u64(path).await {
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "jetson_fan_rpm",
                        rpm as f64,
                        "rpm",
                        0.0,
                        Severity::Low,
                        &[],
                    )
                    .await;
                }
            }
            if let Some(path) = &jetson.fan_pwm {
                if let Some(pwm) = read_u64(path).await {
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "jetson_fan_pwm",
                        pwm as f64,
                        "raw",
                        0.0,
                        Severity::Low,
                        &[],
                    )
                    .await;
                }
            }
            for sensor in &jetson.power_sensors {
                if let Some(power) = read_i64(&sensor.power_path).await {
                    emit_metric(
                        bus,
                        storage,
                        "embedded",
                        "jetson_power",
                        power as f64,
                        sensor.unit.as_str(),
                        0.0,
                        Severity::Low,
                        &[("rail", sensor.label.clone())],
                    )
                    .await;
                }
            }
        }
    }

    async fn collect_disk_usage(&self, bus: &EventBus, storage: &Storage) {
        let mounts = read_mounts().await;
        for mount in mounts {
            if let Some(usage) = statvfs_usage(&mount.mount_point) {
                if usage.total_bytes == 0 {
                    continue;
                }
                let ratio = (usage.used_bytes as f64 / usage.total_bytes as f64).clamp(0.0, 1.0);
                let attrs = [
                    ("mount", mount.mount_point.clone()),
                    ("device", mount.device.clone()),
                    ("fstype", mount.fstype.clone()),
                    ("used_ratio", format!("{ratio:.4}")),
                ];
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "disk_used_bytes",
                    usage.used_bytes as f64,
                    "bytes",
                    ratio,
                    severity_from_ratio(ratio),
                    &attrs,
                )
                .await;
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "disk_total_bytes",
                    usage.total_bytes as f64,
                    "bytes",
                    0.0,
                    Severity::Low,
                    &attrs,
                )
                .await;
            }
        }
    }

    async fn collect_battery(&self, bus: &EventBus, storage: &Storage) {
        let batteries = read_batteries().await;
        for battery in batteries {
            if let Some(capacity) = battery.capacity_percent {
                let ratio = (capacity as f64 / 100.0).clamp(0.0, 1.0);
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "battery_capacity_percent",
                    capacity as f64,
                    "percent",
                    ratio,
                    severity_from_ratio(1.0 - ratio),
                    &[
                        ("battery", battery.name.clone()),
                        ("status", battery.status.clone().unwrap_or_else(|| "unknown".to_string())),
                    ],
                )
                .await;
            }
            if let Some(power) = battery.power_uw {
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "battery_power",
                    power as f64,
                    "microwatt",
                    0.0,
                    Severity::Low,
                    &[("battery", battery.name.clone())],
                )
                .await;
            }
            if let Some(voltage) = battery.voltage_uv {
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "battery_voltage",
                    voltage as f64,
                    "microvolt",
                    0.0,
                    Severity::Low,
                    &[("battery", battery.name.clone())],
                )
                .await;
            }
            if let Some(current) = battery.current_ua {
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "battery_current",
                    current as f64,
                    "microamp",
                    0.0,
                    Severity::Low,
                    &[("battery", battery.name.clone())],
                )
                .await;
            }
        }
    }

    async fn collect_processes(&mut self, bus: &EventBus, storage: &Storage) {
        if !self.config.process_enabled {
            return;
        }
        let since_last = self.proc_last.elapsed();
        if since_last < Duration::from_millis(self.config.process_window_ms) {
            return;
        }
        let elapsed = since_last.as_secs_f64().max(0.001);
        self.proc_last = Instant::now();

        let total_cpu = match read_cpu_total().await {
            Some(total) => total,
            None => {
                self.proc_prev.clear();
                self.proc_prev_total = None;
                return;
            }
        };
        let page_size = page_size();
        let current = read_process_samples(self.config.process_max, page_size).await;
        let prev_total = self.proc_prev_total.unwrap_or(total_cpu);
        let delta_total = total_cpu.saturating_sub(prev_total);

        if !self.proc_prev.is_empty() && delta_total > 0 {
            let mut cpu_rank: Vec<ProcRank> = Vec::new();
            let mut mem_rank: Vec<ProcRank> = Vec::new();
            let mut io_rank: Vec<ProcIoRank> = Vec::new();

            for (pid, sample) in &current {
                mem_rank.push(ProcRank {
                    pid: *pid,
                    name: sample.name.clone(),
                    value: sample.rss_bytes as f64,
                });
                if let Some(prev) = self.proc_prev.get(pid) {
                    let delta_cpu = sample.cpu_time.saturating_sub(prev.cpu_time) as f64;
                    let cpu_percent = (delta_cpu / delta_total as f64 * 100.0).max(0.0);
                    if cpu_percent > 0.0 {
                        cpu_rank.push(ProcRank {
                            pid: *pid,
                            name: sample.name.clone(),
                            value: cpu_percent,
                        });
                    }
                    let delta_read = sample.read_bytes.saturating_sub(prev.read_bytes);
                    let delta_write = sample.write_bytes.saturating_sub(prev.write_bytes);
                    let io_bps = (delta_read + delta_write) as f64 / elapsed;
                    if io_bps > 0.0 {
                        io_rank.push(ProcIoRank {
                            pid: *pid,
                            name: sample.name.clone(),
                            total_bps: io_bps,
                            read_bps: delta_read as f64 / elapsed,
                            write_bps: delta_write as f64 / elapsed,
                        });
                    }
                }
            }

            cpu_rank.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap_or(std::cmp::Ordering::Equal));
            mem_rank.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap_or(std::cmp::Ordering::Equal));
            io_rank.sort_by(|a, b| b.total_bps.partial_cmp(&a.total_bps).unwrap_or(std::cmp::Ordering::Equal));

            let mem_total = self.mem_total_bytes.unwrap_or(0) as f64;
            for entry in cpu_rank.into_iter().take(self.config.process_top_n) {
                let ratio = (entry.value / 100.0).clamp(0.0, 1.0);
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "process_cpu_percent",
                    entry.value,
                    "percent",
                    ratio,
                    severity_from_ratio(ratio),
                    &[
                        ("pid", entry.pid.to_string()),
                        ("process", entry.name.clone()),
                    ],
                )
                .await;
            }
            for entry in mem_rank.into_iter().take(self.config.process_top_n) {
                let ratio = if mem_total > 0.0 {
                    (entry.value / mem_total).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "process_mem_rss_bytes",
                    entry.value,
                    "bytes",
                    ratio,
                    severity_from_ratio(ratio),
                    &[
                        ("pid", entry.pid.to_string()),
                        ("process", entry.name.clone()),
                    ],
                )
                .await;
            }
            for entry in io_rank.into_iter().take(self.config.process_top_n) {
                let ratio = track_rate(
                    &mut self.proc_io_max,
                    &format!("pid:{}", entry.pid),
                    entry.total_bps,
                );
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "process_io_bps",
                    entry.total_bps,
                    "bytes_per_sec",
                    ratio,
                    Severity::Low,
                    &[
                        ("pid", entry.pid.to_string()),
                        ("process", entry.name.clone()),
                        ("read_bps", format!("{:.3}", entry.read_bps)),
                        ("write_bps", format!("{:.3}", entry.write_bps)),
                    ],
                )
                .await;
            }
        }

        self.proc_prev = current;
        self.proc_prev_total = Some(total_cpu);
    }

    async fn collect_gpus(&self, bus: &EventBus, storage: &Storage) {
        if !self.config.gpu_enabled {
            return;
        }

        let mut samples = Vec::new();
        let mut nvml_present = false;
        let mut rocm_present = false;

        if self.config.gpu_nvml_enabled {
            if let Some(nvml) = read_nvml_samples(self.config.gpu_max_devices).await {
                if !nvml.is_empty() {
                    nvml_present = true;
                }
                samples.extend(nvml);
            }
        }

        if self.config.gpu_rocm_enabled {
            if let Some(rocm) = read_rocm_samples(self.config.gpu_max_devices).await {
                if !rocm.is_empty() {
                    rocm_present = true;
                }
                samples.extend(rocm);
            }
        }

        if self.config.gpu_sysfs_enabled {
            let sysfs = read_gpu_sysfs(self.config.gpu_max_devices, nvml_present, rocm_present).await;
            samples.extend(sysfs);
        }

        for gpu in samples {
            let base_attrs = [
                ("gpu_id", gpu.id.clone()),
                ("gpu_vendor", gpu.vendor.clone()),
                ("gpu_source", gpu.source.clone()),
                ("gpu_name", gpu.name.unwrap_or_else(|| "unknown".to_string())),
            ];
            if let Some(util) = gpu.util_percent {
                let ratio = (util / 100.0).clamp(0.0, 1.0);
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "gpu_util_percent",
                    util,
                    "percent",
                    ratio,
                    severity_from_ratio(ratio),
                    &base_attrs,
                )
                .await;
            }
            if let Some(temp) = gpu.temp_c {
                let ratio = (temp / 100.0).clamp(0.0, 1.0);
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "gpu_temp_c",
                    temp,
                    "celsius",
                    ratio,
                    severity_from_ratio(ratio),
                    &base_attrs,
                )
                .await;
            }
            if let Some(total) = gpu.mem_total_bytes {
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "gpu_mem_total_bytes",
                    total as f64,
                    "bytes",
                    0.0,
                    Severity::Low,
                    &base_attrs,
                )
                .await;
            }
            if let Some(used) = gpu.mem_used_bytes {
                let ratio = gpu
                    .mem_total_bytes
                    .map(|total| (used as f64 / total as f64).clamp(0.0, 1.0))
                    .unwrap_or(0.0);
                emit_metric(
                    bus,
                    storage,
                    "embedded",
                    "gpu_mem_used_bytes",
                    used as f64,
                    "bytes",
                    ratio,
                    severity_from_ratio(ratio),
                    &base_attrs,
                )
                .await;
            }
        }
    }

}

fn track_rate(cache: &mut HashMap<String, f64>, key: &str, value: f64) -> f64 {
    let entry = cache.entry(key.to_string()).or_insert(value.max(1.0));
    *entry = (*entry * 0.95).max(value).max(1.0);
    (value / *entry).clamp(0.0, 1.0)
}

#[derive(Clone, Copy)]
struct CpuTotals {
    total: u64,
    idle: u64,
}

#[derive(Clone)]
struct IoTotals {
    read_bytes: u64,
    write_bytes: u64,
}

#[derive(Clone)]
struct NetTotals {
    rx_bytes: u64,
    tx_bytes: u64,
}

struct MemInfo {
    total_kb: Option<u64>,
    available_kb: Option<u64>,
    swap_total_kb: Option<u64>,
    swap_free_kb: Option<u64>,
}

struct ThermalReading {
    zone: String,
    sensor_type: String,
    temp_c: f64,
}

struct DiskReading {
    name: String,
    read_bytes: u64,
    write_bytes: u64,
}

impl DiskReading {
    fn totals(&self) -> IoTotals {
        IoTotals {
            read_bytes: self.read_bytes,
            write_bytes: self.write_bytes,
        }
    }
}

struct NetReading {
    iface: String,
    rx_bytes: u64,
    tx_bytes: u64,
}

impl NetReading {
    fn totals(&self) -> NetTotals {
        NetTotals {
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
        }
    }
}

struct ProcSample {
    name: String,
    cpu_time: u64,
    rss_bytes: u64,
    read_bytes: u64,
    write_bytes: u64,
}

struct ProcRank {
    pid: u32,
    name: String,
    value: f64,
}

struct ProcIoRank {
    pid: u32,
    name: String,
    total_bps: f64,
    read_bps: f64,
    write_bps: f64,
}

struct MountEntry {
    device: String,
    mount_point: String,
    fstype: String,
}

struct FsUsage {
    total_bytes: u64,
    used_bytes: u64,
}

struct BatteryReading {
    name: String,
    status: Option<String>,
    capacity_percent: Option<u64>,
    voltage_uv: Option<u64>,
    current_ua: Option<u64>,
    power_uw: Option<u64>,
}

struct GpuSample {
    id: String,
    name: Option<String>,
    vendor: String,
    source: String,
    util_percent: Option<f64>,
    mem_used_bytes: Option<u64>,
    mem_total_bytes: Option<u64>,
    temp_c: Option<f64>,
}

struct JetsonPaths {
    gpu_load: Option<String>,
    gpu_freq: Option<String>,
    fan_pwm: Option<String>,
    fan_rpm: Option<String>,
    power_sensors: Vec<JetsonPowerSensor>,
}

struct JetsonPowerSensor {
    label: String,
    power_path: String,
    unit: String,
}

async fn read_cpu() -> Option<CpuTotals> {
    let raw = fs::read_to_string("/proc/stat").await.ok()?;
    for line in raw.lines() {
        if line.starts_with("cpu ") {
            let mut parts = line.split_whitespace();
            let _ = parts.next();
            let mut values = Vec::new();
            for part in parts {
                if let Ok(val) = part.parse::<u64>() {
                    values.push(val);
                }
            }
            if values.len() < 4 {
                return None;
            }
            let total: u64 = values.iter().sum();
            let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
            return Some(CpuTotals { total, idle });
        }
    }
    None
}

async fn read_cpu_total() -> Option<u64> {
    read_cpu().await.map(|cpu| cpu.total)
}

async fn read_meminfo() -> Option<MemInfo> {
    let raw = fs::read_to_string("/proc/meminfo").await.ok()?;
    let mut info = MemInfo {
        total_kb: None,
        available_kb: None,
        swap_total_kb: None,
        swap_free_kb: None,
    };
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        let value = parts.next().and_then(|v| v.parse::<u64>().ok());
        match key {
            "MemTotal:" => info.total_kb = value,
            "MemAvailable:" => info.available_kb = value,
            "SwapTotal:" => info.swap_total_kb = value,
            "SwapFree:" => info.swap_free_kb = value,
            _ => {}
        }
    }
    Some(info)
}

async fn read_thermals() -> Vec<ThermalReading> {
    let mut readings = Vec::new();
    let Ok(mut dir) = fs::read_dir("/sys/class/thermal").await else {
        return readings;
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("thermal_zone") {
            continue;
        }
        let path = entry.path();
        let sensor_type = read_trimmed(path.join("type")).await.unwrap_or_else(|| "unknown".to_string());
        if let Some(temp_raw) = read_i64(path.join("temp")).await {
            let temp_c = if temp_raw > 1000 { temp_raw as f64 / 1000.0 } else { temp_raw as f64 };
            readings.push(ThermalReading {
                zone: name,
                sensor_type,
                temp_c,
            });
        }
    }
    readings.sort_by(|a, b| a.zone.cmp(&b.zone));
    readings
}

async fn read_disks() -> Option<Vec<DiskReading>> {
    let raw = fs::read_to_string("/proc/diskstats").await.ok()?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            continue;
        }
        let name = parts[2];
        if is_ignored_disk(name) {
            continue;
        }
        let read_sectors = parts[5].parse::<u64>().unwrap_or(0);
        let write_sectors = parts[9].parse::<u64>().unwrap_or(0);
        out.push(DiskReading {
            name: name.to_string(),
            read_bytes: read_sectors.saturating_mul(512),
            write_bytes: write_sectors.saturating_mul(512),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Some(out)
}

async fn read_net() -> Option<Vec<NetReading>> {
    let raw = fs::read_to_string("/proc/net/dev").await.ok()?;
    let mut out = Vec::new();
    for line in raw.lines().skip(2) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(':');
        let iface = parts.next().unwrap_or("").trim();
        if iface.is_empty() || iface == "lo" {
            continue;
        }
        let data = parts.next().unwrap_or("");
        let fields: Vec<&str> = data.split_whitespace().collect();
        if fields.len() < 16 {
            continue;
        }
        let rx_bytes = fields[0].parse::<u64>().unwrap_or(0);
        let tx_bytes = fields[8].parse::<u64>().unwrap_or(0);
        out.push(NetReading {
            iface: iface.to_string(),
            rx_bytes,
            tx_bytes,
        });
    }
    out.sort_by(|a, b| a.iface.cmp(&b.iface));
    Some(out)
}

async fn read_process_samples(max: usize, page_size: u64) -> HashMap<u32, ProcSample> {
    let mut samples = HashMap::new();
    let Ok(mut dir) = fs::read_dir("/proc").await else {
        return samples;
    };
    let mut pids = Vec::new();
    while let Ok(Some(entry)) = dir.next_entry().await {
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    let limit = if max == 0 { pids.len() } else { max.min(pids.len()) };
    for pid in pids.into_iter().take(limit) {
        if let Some(sample) = read_proc_sample(pid, page_size).await {
            samples.insert(pid, sample);
        }
    }
    samples
}

async fn read_proc_sample(pid: u32, page_size: u64) -> Option<ProcSample> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_raw = fs::read_to_string(stat_path).await.ok()?;
    let (name, utime, stime) = parse_proc_stat(&stat_raw)?;
    let cpu_time = utime.saturating_add(stime);

    let statm_path = format!("/proc/{}/statm", pid);
    let statm_raw = fs::read_to_string(statm_path).await.ok().unwrap_or_default();
    let rss_pages = statm_raw
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let rss_bytes = rss_pages.saturating_mul(page_size);

    let (read_bytes, write_bytes) = read_proc_io(pid).await;

    Some(ProcSample {
        name,
        cpu_time,
        rss_bytes,
        read_bytes,
        write_bytes,
    })
}

fn parse_proc_stat(stat: &str) -> Option<(String, u64, u64)> {
    let start = stat.find('(')?;
    let end = stat.rfind(')')?;
    if end <= start {
        return None;
    }
    let name = stat[start + 1..end].to_string();
    let rest = stat.get(end + 2..)?;
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 13 {
        return None;
    }
    let utime = parts.get(11)?.parse::<u64>().ok()?;
    let stime = parts.get(12)?.parse::<u64>().ok()?;
    Some((name, utime, stime))
}

async fn read_proc_io(pid: u32) -> (u64, u64) {
    let path = format!("/proc/{}/io", pid);
    let raw = fs::read_to_string(path).await.ok().unwrap_or_default();
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("read_bytes:") {
            read_bytes = value.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("write_bytes:") {
            write_bytes = value.trim().parse::<u64>().unwrap_or(0);
        }
    }
    (read_bytes, write_bytes)
}

async fn read_mounts() -> Vec<MountEntry> {
    let mut out = Vec::new();
    let raw = fs::read_to_string("/proc/self/mounts").await.unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let device = parts.next().unwrap_or("").to_string();
        let mount_point = unescape_mount(parts.next().unwrap_or(""));
        let fstype = parts.next().unwrap_or("").to_string();
        if mount_point.is_empty() || fstype.is_empty() {
            continue;
        }
        if is_ignored_fstype(&fstype) {
            continue;
        }
        if seen.insert(mount_point.clone()) {
            out.push(MountEntry {
                device,
                mount_point,
                fstype,
            });
        }
    }
    out
}

fn unescape_mount(raw: &str) -> String {
    raw.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn is_ignored_fstype(fstype: &str) -> bool {
    matches!(
        fstype,
        "proc"
            | "sysfs"
            | "tmpfs"
            | "devtmpfs"
            | "devpts"
            | "cgroup"
            | "cgroup2"
            | "mqueue"
            | "hugetlbfs"
            | "rpc_pipefs"
            | "fusectl"
            | "tracefs"
            | "debugfs"
            | "securityfs"
            | "pstore"
            | "efivarfs"
            | "bpf"
    )
}

#[cfg(target_os = "linux")]
fn statvfs_usage(path: &str) -> Option<FsUsage> {
    let c_path = CString::new(path).ok()?;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) };
    if rc != 0 {
        return None;
    }
    let block_size = if vfs.f_frsize == 0 { vfs.f_bsize } else { vfs.f_frsize } as u64;
    let total_bytes = vfs.f_blocks.saturating_mul(block_size);
    let available_bytes = vfs.f_bavail.saturating_mul(block_size);
    let used_bytes = total_bytes.saturating_sub(available_bytes);
    Some(FsUsage {
        total_bytes,
        used_bytes,
    })
}

#[cfg(not(target_os = "linux"))]
fn statvfs_usage(_path: &str) -> Option<FsUsage> {
    None
}

async fn read_batteries() -> Vec<BatteryReading> {
    let mut out = Vec::new();
    let Ok(mut dir) = fs::read_dir("/sys/class/power_supply").await else {
        return out;
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let battery_type = read_trimmed(path.join("type")).await;
        if battery_type.as_deref() != Some("Battery") && !name.starts_with("BAT") {
            continue;
        }

        let status = read_trimmed(path.join("status")).await;
        let mut capacity_percent = read_u64(path.join("capacity")).await;

        if capacity_percent.is_none() {
            if let (Some(now), Some(full)) = (
                read_u64(path.join("energy_now")).await,
                read_u64(path.join("energy_full")).await,
            ) {
                if full > 0 {
                    capacity_percent = Some(now.saturating_mul(100) / full);
                }
            } else if let (Some(now), Some(full)) = (
                read_u64(path.join("charge_now")).await,
                read_u64(path.join("charge_full")).await,
            ) {
                if full > 0 {
                    capacity_percent = Some(now.saturating_mul(100) / full);
                }
            }
        }

        out.push(BatteryReading {
            name,
            status,
            capacity_percent,
            voltage_uv: read_u64(path.join("voltage_now")).await,
            current_ua: read_u64(path.join("current_now")).await,
            power_uw: read_u64(path.join("power_now")).await,
        });
    }
    out
}

async fn read_gpu_sysfs(
    max_devices: usize,
    skip_nvidia: bool,
    skip_amd: bool,
) -> Vec<GpuSample> {
    let mut out = Vec::new();
    let Ok(mut dir) = fs::read_dir("/sys/class/drm").await else {
        return out;
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("card") || name.contains('-') {
            continue;
        }
        let card_path = entry.path();
        let vendor_id = read_trimmed(card_path.join("device/vendor")).await;
        let vendor = vendor_from_id(vendor_id.as_deref());
        if skip_nvidia && vendor == "nvidia" {
            continue;
        }
        if skip_amd && vendor == "amd" {
            continue;
        }

        let util_percent = read_gpu_busy(&card_path).await;
        let (mem_used, mem_total) = read_gpu_mem(&card_path).await;
        let temp_c = read_hwmon_temp(&card_path).await;
        let gpu_name = read_trimmed(card_path.join("device/uevent"))
            .await
            .and_then(|raw| raw.lines().find_map(|line| line.strip_prefix("DRIVER=")).map(|v| v.to_string()));

        if util_percent.is_none() && mem_used.is_none() && mem_total.is_none() && temp_c.is_none() {
            continue;
        }

        out.push(GpuSample {
            id: name.clone(),
            name: gpu_name.or_else(|| Some(name.clone())),
            vendor: vendor.to_string(),
            source: "sysfs".to_string(),
            util_percent,
            mem_used_bytes: mem_used,
            mem_total_bytes: mem_total,
            temp_c,
        });
        if out.len() >= max_devices {
            break;
        }
    }
    out
}

fn vendor_from_id(id: Option<&str>) -> &'static str {
    match id.unwrap_or("").trim() {
        "0x10de" => "nvidia",
        "0x1002" => "amd",
        "0x8086" => "intel",
        _ => "unknown",
    }
}

async fn read_gpu_busy(card_path: &Path) -> Option<f64> {
    let candidates = [
        card_path.join("device/gpu_busy_percent"),
        card_path.join("device/gt_busy_percent"),
        card_path.join("gt_busy_percent"),
        card_path.join("device/engine_busy_percent"),
    ];
    for path in candidates {
        if let Some(value) = read_u64(path).await {
            return Some(value as f64);
        }
    }
    None
}

async fn read_gpu_mem(card_path: &Path) -> (Option<u64>, Option<u64>) {
    let total = read_u64(card_path.join("device/mem_info_vram_total")).await;
    let used = read_u64(card_path.join("device/mem_info_vram_used")).await;
    if total.is_some() || used.is_some() {
        return (used, total);
    }
    let total = read_u64(card_path.join("device/mem_info_gtt_total")).await;
    let used = read_u64(card_path.join("device/mem_info_gtt_used")).await;
    (used, total)
}

async fn read_hwmon_temp(card_path: &Path) -> Option<f64> {
    let hwmon = card_path.join("device/hwmon");
    let Ok(mut dir) = fs::read_dir(hwmon).await else {
        return None;
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let base = entry.path();
        let Ok(mut files) = fs::read_dir(&base).await else {
            continue;
        };
        while let Ok(Some(file)) = files.next_entry().await {
            let name = file.file_name().to_string_lossy().to_string();
            if name.starts_with("temp") && name.ends_with("_input") {
                if let Some(raw) = read_i64(file.path()).await {
                    let temp = if raw > 1000 { raw as f64 / 1000.0 } else { raw as f64 };
                    return Some(temp);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
async fn read_nvml_samples(max_devices: usize) -> Option<Vec<GpuSample>> {
    tokio::task::spawn_blocking(move || nvml_samples_sync(max_devices))
        .await
        .ok()
        .flatten()
}

#[cfg(not(target_os = "linux"))]
async fn read_nvml_samples(_max_devices: usize) -> Option<Vec<GpuSample>> {
    None
}

#[cfg(target_os = "linux")]
async fn read_rocm_samples(max_devices: usize) -> Option<Vec<GpuSample>> {
    tokio::task::spawn_blocking(move || rocm_samples_sync(max_devices))
        .await
        .ok()
        .flatten()
}

#[cfg(not(target_os = "linux"))]
async fn read_rocm_samples(_max_devices: usize) -> Option<Vec<GpuSample>> {
    None
}

#[cfg(target_os = "linux")]
fn nvml_samples_sync(max_devices: usize) -> Option<Vec<GpuSample>> {
    use libloading::Library;
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    const NVML_SUCCESS: c_int = 0;
    const NVML_TEMPERATURE_GPU: c_uint = 0;

    #[repr(C)]
    struct NvmlUtilization {
        gpu: c_uint,
        memory: c_uint,
    }

    #[repr(C)]
    struct NvmlMemory {
        total: u64,
        free: u64,
        used: u64,
    }

    type NvmlDevice = *mut c_void;
    type NvmlInit = unsafe extern "C" fn() -> c_int;
    type NvmlShutdown = unsafe extern "C" fn() -> c_int;
    type NvmlDeviceGetCount = unsafe extern "C" fn(*mut c_uint) -> c_int;
    type NvmlDeviceGetHandle = unsafe extern "C" fn(c_uint, *mut NvmlDevice) -> c_int;
    type NvmlDeviceGetUtil = unsafe extern "C" fn(NvmlDevice, *mut NvmlUtilization) -> c_int;
    type NvmlDeviceGetTemp = unsafe extern "C" fn(NvmlDevice, c_uint, *mut c_uint) -> c_int;
    type NvmlDeviceGetName = unsafe extern "C" fn(NvmlDevice, *mut c_char, c_uint) -> c_int;
    type NvmlDeviceGetMemory = unsafe extern "C" fn(NvmlDevice, *mut NvmlMemory) -> c_int;

    let lib = unsafe { Library::new("libnvidia-ml.so.1") }
        .or_else(|_| unsafe { Library::new("libnvidia-ml.so") })
        .ok()?;

    unsafe {
        let nvml_init: libloading::Symbol<NvmlInit> = lib.get(b"nvmlInit_v2\0").ok()?;
        let nvml_shutdown: libloading::Symbol<NvmlShutdown> = lib.get(b"nvmlShutdown\0").ok()?;
        let nvml_count: libloading::Symbol<NvmlDeviceGetCount> =
            lib.get(b"nvmlDeviceGetCount_v2\0").ok()?;
        let nvml_handle: libloading::Symbol<NvmlDeviceGetHandle> =
            lib.get(b"nvmlDeviceGetHandleByIndex_v2\0").ok()?;
        let nvml_util: libloading::Symbol<NvmlDeviceGetUtil> =
            lib.get(b"nvmlDeviceGetUtilizationRates\0").ok()?;
        let nvml_temp: libloading::Symbol<NvmlDeviceGetTemp> =
            lib.get(b"nvmlDeviceGetTemperature\0").ok()?;
        let nvml_name: libloading::Symbol<NvmlDeviceGetName> =
            lib.get(b"nvmlDeviceGetName\0").ok()?;
        let nvml_mem: libloading::Symbol<NvmlDeviceGetMemory> =
            lib.get(b"nvmlDeviceGetMemoryInfo\0").ok()?;

        if nvml_init() != NVML_SUCCESS {
            return None;
        }

        let mut count: c_uint = 0;
        if nvml_count(&mut count as *mut c_uint) != NVML_SUCCESS {
            let _ = nvml_shutdown();
            return None;
        }

        let mut out = Vec::new();
        let device_count = count.min(max_devices as c_uint);
        for idx in 0..device_count {
            let mut device: NvmlDevice = std::ptr::null_mut();
            if nvml_handle(idx, &mut device as *mut NvmlDevice) != NVML_SUCCESS {
                continue;
            }

            let mut name_buf = [0 as c_char; 96];
            let name = if nvml_name(device, name_buf.as_mut_ptr(), name_buf.len() as c_uint)
                == NVML_SUCCESS
            {
                let cstr = std::ffi::CStr::from_ptr(name_buf.as_ptr());
                cstr.to_str().ok().map(|s| s.to_string())
            } else {
                None
            };

            let mut util = NvmlUtilization { gpu: 0, memory: 0 };
            let util_percent = if nvml_util(device, &mut util as *mut NvmlUtilization)
                == NVML_SUCCESS
            {
                Some(util.gpu as f64)
            } else {
                None
            };

            let mut temp_val: c_uint = 0;
            let temp_c = if nvml_temp(device, NVML_TEMPERATURE_GPU, &mut temp_val as *mut c_uint)
                == NVML_SUCCESS
            {
                Some(temp_val as f64)
            } else {
                None
            };

            let mut mem = NvmlMemory {
                total: 0,
                free: 0,
                used: 0,
            };
            let (mem_total, mem_used) = if nvml_mem(device, &mut mem as *mut NvmlMemory)
                == NVML_SUCCESS
            {
                (Some(mem.total), Some(mem.used))
            } else {
                (None, None)
            };

            out.push(GpuSample {
                id: format!("nvml:{}", idx),
                name,
                vendor: "nvidia".to_string(),
                source: "nvml".to_string(),
                util_percent,
                mem_used_bytes: mem_used,
                mem_total_bytes: mem_total,
                temp_c,
            });
        }

        let _ = nvml_shutdown();
        Some(out)
    }
}

#[cfg(target_os = "linux")]
fn rocm_samples_sync(max_devices: usize) -> Option<Vec<GpuSample>> {
    use libloading::Library;
    use std::os::raw::{c_char, c_int, c_uint, c_ulonglong};

    const RSMI_SUCCESS: c_int = 0;
    const RSMI_TEMP_TYPE_EDGE: c_uint = 0;
    const RSMI_TEMP_CURRENT: c_uint = 0;
    const RSMI_MEM_TYPE_VRAM: c_uint = 0;

    type RsmiInit = unsafe extern "C" fn(c_ulonglong) -> c_int;
    type RsmiShutdown = unsafe extern "C" fn() -> c_int;
    type RsmiGetCount = unsafe extern "C" fn(*mut c_uint) -> c_int;
    type RsmiGetName = unsafe extern "C" fn(c_uint, *mut c_char, usize) -> c_int;
    type RsmiGetUtil = unsafe extern "C" fn(c_uint, *mut c_uint) -> c_int;
    type RsmiGetTemp = unsafe extern "C" fn(c_uint, c_uint, c_uint, *mut i64) -> c_int;
    type RsmiGetMemTotal = unsafe extern "C" fn(c_uint, c_uint, *mut u64) -> c_int;
    type RsmiGetMemUsage = unsafe extern "C" fn(c_uint, c_uint, *mut u64) -> c_int;

    let lib = unsafe { Library::new("librocm_smi64.so.5") }
        .or_else(|_| unsafe { Library::new("librocm_smi64.so.6") })
        .or_else(|_| unsafe { Library::new("librocm_smi64.so") })
        .ok()?;

    unsafe {
        let rsmi_init: libloading::Symbol<RsmiInit> = lib.get(b"rsmi_init\0").ok()?;
        let rsmi_shutdown: libloading::Symbol<RsmiShutdown> = lib.get(b"rsmi_shut_down\0").ok()?;
        let rsmi_count: libloading::Symbol<RsmiGetCount> =
            lib.get(b"rsmi_num_monitor_devices\0").ok()?;
        let rsmi_name: libloading::Symbol<RsmiGetName> = lib.get(b"rsmi_dev_name_get\0").ok()?;
        let rsmi_util: libloading::Symbol<RsmiGetUtil> =
            lib.get(b"rsmi_dev_busy_percent_get\0").ok()?;
        let rsmi_temp: libloading::Symbol<RsmiGetTemp> =
            lib.get(b"rsmi_dev_temp_metric_get\0").ok()?;
        let rsmi_mem_total: libloading::Symbol<RsmiGetMemTotal> =
            lib.get(b"rsmi_dev_memory_total_get\0").ok()?;
        let rsmi_mem_used: libloading::Symbol<RsmiGetMemUsage> =
            lib.get(b"rsmi_dev_memory_usage_get\0").ok()?;

        if rsmi_init(0) != RSMI_SUCCESS {
            return None;
        }

        let mut count: c_uint = 0;
        if rsmi_count(&mut count as *mut c_uint) != RSMI_SUCCESS {
            let _ = rsmi_shutdown();
            return None;
        }

        let mut out = Vec::new();
        let device_count = count.min(max_devices as c_uint);
        for idx in 0..device_count {
            let mut name_buf = [0 as c_char; 96];
            let name = if rsmi_name(idx, name_buf.as_mut_ptr(), name_buf.len()) == RSMI_SUCCESS {
                let cstr = std::ffi::CStr::from_ptr(name_buf.as_ptr());
                cstr.to_str().ok().map(|s| s.to_string())
            } else {
                None
            };

            let mut util = 0u32;
            let util_percent = if rsmi_util(idx, &mut util as *mut c_uint) == RSMI_SUCCESS {
                Some(util as f64)
            } else {
                None
            };

            let mut temp_val: i64 = 0;
            let temp_c = if rsmi_temp(
                idx,
                RSMI_TEMP_TYPE_EDGE,
                RSMI_TEMP_CURRENT,
                &mut temp_val as *mut i64,
            ) == RSMI_SUCCESS
            {
                let value = if temp_val > 1000 { temp_val as f64 / 1000.0 } else { temp_val as f64 };
                Some(value)
            } else {
                None
            };

            let mut mem_total: u64 = 0;
            let mem_total = if rsmi_mem_total(idx, RSMI_MEM_TYPE_VRAM, &mut mem_total as *mut u64)
                == RSMI_SUCCESS
            {
                Some(mem_total)
            } else {
                None
            };

            let mut mem_used: u64 = 0;
            let mem_used = if rsmi_mem_used(idx, RSMI_MEM_TYPE_VRAM, &mut mem_used as *mut u64)
                == RSMI_SUCCESS
            {
                Some(mem_used)
            } else {
                None
            };

            if util_percent.is_none() && mem_total.is_none() && mem_used.is_none() && temp_c.is_none() {
                continue;
            }

            out.push(GpuSample {
                id: format!("rocm:{}", idx),
                name,
                vendor: "amd".to_string(),
                source: "rocm_smi".to_string(),
                util_percent,
                mem_used_bytes: mem_used,
                mem_total_bytes: mem_total,
                temp_c,
            });
        }

        let _ = rsmi_shutdown();
        Some(out)
    }
}

fn rate_bytes(current: u64, previous: u64, elapsed: f64) -> f64 {
    let delta = current.saturating_sub(previous) as f64;
    (delta / elapsed).max(0.0)
}

fn page_size() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if value <= 0 {
            4096
        } else {
            value as u64
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        4096
    }
}

fn is_ignored_disk(name: &str) -> bool {
    name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("fd")
        || name.starts_with("sr")
}

async fn read_trimmed(path: PathBuf) -> Option<String> {
    let raw = fs::read_to_string(path).await.ok()?;
    let value = raw.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    if value.is_empty() { None } else { Some(value.to_string()) }
}

async fn read_u64<P: AsRef<Path>>(path: P) -> Option<u64> {
    read_i64(path).await.and_then(|v| if v >= 0 { Some(v as u64) } else { None })
}

async fn read_u64_opt(path: &Option<String>) -> Option<u64> {
    let Some(path) = path else { return None; };
    read_u64(path).await
}

async fn read_i64<P: AsRef<Path>>(path: P) -> Option<i64> {
    let raw = fs::read_to_string(path).await.ok()?;
    raw.trim().parse::<i64>().ok()
}

fn severity_from_ratio(ratio: f64) -> Severity {
    if ratio >= 0.9 {
        Severity::High
    } else if ratio >= 0.75 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

async fn emit_metric(
    bus: &EventBus,
    storage: &Storage,
    source: &str,
    metric: &str,
    value: f64,
    unit: &str,
    signal: f64,
    severity: Severity,
    attrs: &[(&str, String)],
) {
    let id = EMBEDDED_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut event = Event::new(id, source, EventKind::SystemMetric, signal, severity)
        .with_attr("metric", metric)
        .with_attr("value", format!("{value:.3}"))
        .with_attr("unit", unit);
    for (key, value) in attrs {
        event = event.with_attr(*key, value.clone());
    }
    bus.publish(event.clone());
    storage.record_event(event).await;
}

async fn discover_jetson_paths() -> Option<JetsonPaths> {
    let gpu_load = find_first_existing(&[
        "/sys/devices/platform/gpu.0/load",
        "/sys/devices/17000000.gp10b/load",
        "/sys/devices/17000000.gv11b/load",
        "/sys/devices/17000000.ga10b/load",
    ])
    .await;

    let gpu_freq = find_first_existing(&[
        "/sys/devices/platform/gpu.0/devfreq/57000000.gpu/cur_freq",
        "/sys/devices/platform/gpu.0/devfreq/57000000.gpu/devfreq/cur_freq",
        "/sys/devices/17000000.gv11b/devfreq/17000000.gv11b/cur_freq",
        "/sys/devices/17000000.ga10b/devfreq/17000000.ga10b/cur_freq",
    ])
    .await;

    let (fan_pwm, fan_rpm) = find_fan_paths().await;
    let power_sensors = find_ina_power_sensors().await;

    if gpu_load.is_none()
        && gpu_freq.is_none()
        && fan_pwm.is_none()
        && fan_rpm.is_none()
        && power_sensors.is_empty()
    {
        None
    } else {
        Some(JetsonPaths {
            gpu_load,
            gpu_freq,
            fan_pwm,
            fan_rpm,
            power_sensors,
        })
    }
}

async fn find_first_existing(candidates: &[&str]) -> Option<String> {
    for path in candidates {
        if fs::metadata(path).await.is_ok() {
            return Some(path.to_string());
        }
    }
    None
}

async fn find_fan_paths() -> (Option<String>, Option<String>) {
    let base = Path::new("/sys/devices/platform/pwm-fan/hwmon");
    let Ok(mut dir) = fs::read_dir(base).await else {
        return (None, None);
    };
    let mut pwm = None;
    let mut rpm = None;
    while let Ok(Some(entry)) = dir.next_entry().await {
        let path = entry.path();
        let pwm_path = path.join("pwm1");
        let rpm_path = path.join("fan1_input");
        if pwm.is_none() && fs::metadata(&pwm_path).await.is_ok() {
            pwm = Some(pwm_path.to_string_lossy().to_string());
        }
        if rpm.is_none() && fs::metadata(&rpm_path).await.is_ok() {
            rpm = Some(rpm_path.to_string_lossy().to_string());
        }
        if pwm.is_some() && rpm.is_some() {
            break;
        }
    }
    (pwm, rpm)
}

async fn find_ina_power_sensors() -> Vec<JetsonPowerSensor> {
    let mut sensors = Vec::new();
    let base = Path::new("/sys/bus/i2c/drivers/ina3221x");
    let Ok(mut dir) = fs::read_dir(base).await else {
        return sensors;
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let path = entry.path();
        let Ok(mut sub) = fs::read_dir(&path).await else {
            continue;
        };
        while let Ok(Some(sub_entry)) = sub.next_entry().await {
            let dev_path = sub_entry.path();
            if dev_path.file_name().and_then(|n| n.to_str()).unwrap_or("").starts_with("iio:device") {
                collect_iio_power(&dev_path, &mut sensors).await;
            }
        }
    }
    sensors
}

async fn collect_iio_power(path: &Path, sensors: &mut Vec<JetsonPowerSensor>) {
    let Ok(mut dir) = fs::read_dir(path).await else {
        return;
    };
    let mut labels: HashMap<String, String> = HashMap::new();
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("rail_name_") {
            if let Ok(raw) = fs::read_to_string(entry.path()).await {
                let label = raw.trim().to_string();
                labels.insert(name, label);
            }
        }
    }

    let Ok(mut dir) = fs::read_dir(path).await else {
        return;
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("in_power") && name.ends_with("_input") {
            let label_key = name
                .strip_prefix("in_power")
                .and_then(|v| v.strip_suffix("_input"))
                .map(|idx| format!("rail_name_{}", idx))
                .unwrap_or_else(|| "rail_name".to_string());
            let label = labels
                .get(&label_key)
                .cloned()
                .unwrap_or_else(|| label_key.clone());
            sensors.push(JetsonPowerSensor {
                label,
                power_path: entry.path().to_string_lossy().to_string(),
                unit: "microwatt".to_string(),
            });
        }
        if name.starts_with("in_current") && name.ends_with("_input") {
            let label_key = name
                .strip_prefix("in_current")
                .and_then(|v| v.strip_suffix("_input"))
                .map(|idx| format!("rail_name_{}", idx))
                .unwrap_or_else(|| "rail_name".to_string());
            let label = labels
                .get(&label_key)
                .cloned()
                .unwrap_or_else(|| label_key.clone());
            sensors.push(JetsonPowerSensor {
                label,
                power_path: entry.path().to_string_lossy().to_string(),
                unit: "microamp".to_string(),
            });
        }
    }
}
