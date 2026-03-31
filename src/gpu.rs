//! Shared GPU discovery and sampling backends used by embedded telemetry and
//! TraceyGuard scheduling.

use crate::config::EmbeddedConfig;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::fs;

#[derive(Clone, Debug)]
pub struct GpuBackendConfig {
    pub sysfs_enabled: bool,
    pub nvml_enabled: bool,
    pub rocm_enabled: bool,
    pub max_devices: usize,
}

impl GpuBackendConfig {
    pub fn from_embedded_with_limit(config: &EmbeddedConfig, max_devices: usize) -> Self {
        Self {
            sysfs_enabled: config.gpu_sysfs_enabled,
            nvml_enabled: config.gpu_nvml_enabled,
            rocm_enabled: config.gpu_rocm_enabled,
            max_devices: max_devices.max(1),
        }
    }

    pub fn any_enabled(&self) -> bool {
        self.sysfs_enabled || self.nvml_enabled || self.rocm_enabled
    }
}

impl From<&EmbeddedConfig> for GpuBackendConfig {
    fn from(config: &EmbeddedConfig) -> Self {
        let enabled = config.gpu_enabled;
        Self {
            sysfs_enabled: enabled && config.gpu_sysfs_enabled,
            nvml_enabled: enabled && config.gpu_nvml_enabled,
            rocm_enabled: enabled && config.gpu_rocm_enabled,
            max_devices: config.gpu_max_devices.max(1),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct GpuDescriptor {
    pub id: String,
    pub name: Option<String>,
    pub vendor: String,
    pub source: String,
}

#[derive(Clone, Debug, Default)]
pub struct GpuSample {
    pub id: String,
    pub name: Option<String>,
    pub vendor: String,
    pub source: String,
    pub util_percent: Option<f64>,
    pub mem_used_bytes: Option<u64>,
    pub mem_total_bytes: Option<u64>,
    pub temp_c: Option<f64>,
    pub power_w: Option<f64>,
    pub graphics_clock_mhz: Option<u64>,
    pub memory_clock_mhz: Option<u64>,
    pub fan_speed_percent: Option<u32>,
    pub encoder_util_percent: Option<u32>,
    pub decoder_util_percent: Option<u32>,
}

impl GpuSample {
    pub fn descriptor(&self) -> GpuDescriptor {
        GpuDescriptor {
            id: self.id.clone(),
            name: self.name.clone(),
            vendor: self.vendor.clone(),
            source: self.source.clone(),
        }
    }
}

pub async fn collect_samples(config: &GpuBackendConfig) -> Vec<GpuSample> {
    if std::env::consts::OS != "linux" || !config.any_enabled() {
        return Vec::new();
    }

    let max_devices = config.max_devices.max(1);
    let nvml_task = async {
        if config.nvml_enabled {
            read_nvml_samples(max_devices).await
        } else {
            Vec::new()
        }
    };
    let rocm_task = async {
        if config.rocm_enabled {
            read_rocm_samples(max_devices).await
        } else {
            Vec::new()
        }
    };

    let (mut nvml, mut rocm) = tokio::join!(nvml_task, rocm_task);
    let nvml_present = !nvml.is_empty();
    let rocm_present = !rocm.is_empty();

    let mut samples = Vec::with_capacity(nvml.len() + rocm.len() + max_devices);
    samples.append(&mut nvml);
    samples.append(&mut rocm);
    if config.sysfs_enabled {
        samples.extend(read_gpu_sysfs(max_devices, nvml_present, rocm_present).await);
    }

    dedup_samples(samples, max_devices)
}

pub async fn discover_devices(config: &GpuBackendConfig) -> Vec<GpuDescriptor> {
    if std::env::consts::OS != "linux" || !config.any_enabled() {
        return Vec::new();
    }

    let samples = collect_samples(config).await;
    if !samples.is_empty() {
        return samples
            .into_iter()
            .map(|sample| sample.descriptor())
            .collect();
    }

    if config.sysfs_enabled {
        return read_gpu_sysfs_devices(config.max_devices.max(1), false, false)
            .await
            .into_iter()
            .map(|device| device.descriptor())
            .collect();
    }

    Vec::new()
}

fn dedup_samples(samples: Vec<GpuSample>, max_devices: usize) -> Vec<GpuSample> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(samples.len().min(max_devices));
    for sample in samples {
        if seen.insert(sample.id.clone()) {
            out.push(sample);
            if out.len() >= max_devices {
                break;
            }
        }
    }
    out
}

#[derive(Clone, Debug)]
struct SysfsGpuDevice {
    id: String,
    name: Option<String>,
    vendor: String,
    card_path: PathBuf,
}

impl SysfsGpuDevice {
    fn descriptor(self) -> GpuDescriptor {
        GpuDescriptor {
            id: self.id,
            name: self.name,
            vendor: self.vendor,
            source: "sysfs".to_string(),
        }
    }
}

async fn read_gpu_sysfs_devices(
    max_devices: usize,
    skip_nvidia: bool,
    skip_amd: bool,
) -> Vec<SysfsGpuDevice> {
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

        let gpu_name = read_trimmed(card_path.join("device/uevent"))
            .await
            .and_then(|raw| {
                raw.lines()
                    .find_map(|line| line.strip_prefix("DRIVER="))
                    .map(|value| value.to_string())
            })
            .or_else(|| Some(name.clone()));

        out.push(SysfsGpuDevice {
            id: name,
            name: gpu_name,
            vendor: vendor.to_string(),
            card_path,
        });
        if out.len() >= max_devices {
            break;
        }
    }
    out
}

async fn read_gpu_sysfs(max_devices: usize, skip_nvidia: bool, skip_amd: bool) -> Vec<GpuSample> {
    let devices = read_gpu_sysfs_devices(max_devices, skip_nvidia, skip_amd).await;
    let mut out = Vec::new();
    for device in devices {
        let util_percent = read_gpu_busy(&device.card_path).await;
        let (mem_used, mem_total) = read_gpu_mem(&device.card_path).await;
        let temp_c = read_hwmon_temp(&device.card_path).await;

        if util_percent.is_none() && mem_used.is_none() && mem_total.is_none() && temp_c.is_none() {
            continue;
        }

        out.push(GpuSample {
            id: device.id,
            name: device.name,
            vendor: device.vendor,
            source: "sysfs".to_string(),
            util_percent,
            mem_used_bytes: mem_used,
            mem_total_bytes: mem_total,
            temp_c,
            power_w: None,
            graphics_clock_mhz: None,
            memory_clock_mhz: None,
            fan_speed_percent: None,
            encoder_util_percent: None,
            decoder_util_percent: None,
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
                    let temp = if raw > 1000 {
                        raw as f64 / 1000.0
                    } else {
                        raw as f64
                    };
                    return Some(temp);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
async fn read_nvml_samples(max_devices: usize) -> Vec<GpuSample> {
    tokio::task::spawn_blocking(move || nvml_samples_sync(max_devices))
        .await
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
async fn read_nvml_samples(_max_devices: usize) -> Vec<GpuSample> {
    Vec::new()
}

#[cfg(target_os = "linux")]
async fn read_rocm_samples(max_devices: usize) -> Vec<GpuSample> {
    tokio::task::spawn_blocking(move || rocm_samples_sync(max_devices))
        .await
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
async fn read_rocm_samples(_max_devices: usize) -> Vec<GpuSample> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn nvml_samples_sync(max_devices: usize) -> Vec<GpuSample> {
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    const NVML_SUCCESS: c_int = 0;
    const NVML_TEMPERATURE_GPU: c_uint = 0;
    const NVML_CLOCK_GRAPHICS: c_uint = 0;
    const NVML_CLOCK_MEM: c_uint = 2;

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
    type NvmlDeviceGetName = unsafe extern "C" fn(NvmlDevice, *mut c_char, c_uint) -> c_int;
    type NvmlDeviceGetUtil = unsafe extern "C" fn(NvmlDevice, *mut NvmlUtilization) -> c_int;
    type NvmlDeviceGetTemp = unsafe extern "C" fn(NvmlDevice, c_uint, *mut c_uint) -> c_int;
    type NvmlDeviceGetPower = unsafe extern "C" fn(NvmlDevice, *mut c_uint) -> c_int;
    type NvmlDeviceGetClock = unsafe extern "C" fn(NvmlDevice, c_uint, *mut c_uint) -> c_int;
    type NvmlDeviceGetMemory = unsafe extern "C" fn(NvmlDevice, *mut NvmlMemory) -> c_int;
    type NvmlDeviceGetFan = unsafe extern "C" fn(NvmlDevice, *mut c_uint) -> c_int;
    type NvmlDeviceGetCodecUtil =
        unsafe extern "C" fn(NvmlDevice, *mut c_uint, *mut c_uint) -> c_int;

    struct NvmlApi {
        init: NvmlInit,
        shutdown: NvmlShutdown,
        count: NvmlDeviceGetCount,
        handle: NvmlDeviceGetHandle,
        name: Option<NvmlDeviceGetName>,
        util: Option<NvmlDeviceGetUtil>,
        temp: Option<NvmlDeviceGetTemp>,
        power: Option<NvmlDeviceGetPower>,
        clock: Option<NvmlDeviceGetClock>,
        memory: Option<NvmlDeviceGetMemory>,
        fan: Option<NvmlDeviceGetFan>,
        encoder: Option<NvmlDeviceGetCodecUtil>,
        decoder: Option<NvmlDeviceGetCodecUtil>,
    }

    fn nvml_api() -> Option<&'static NvmlApi> {
        static API: OnceLock<Option<NvmlApi>> = OnceLock::new();
        API.get_or_init(|| unsafe { load_nvml_api() }).as_ref()
    }

    unsafe fn load_symbol<T: Copy>(lib: &libloading::Library, names: &[&[u8]]) -> Option<T> {
        for name in names {
            if let Ok(symbol) = unsafe { lib.get::<T>(name) } {
                return Some(*symbol);
            }
        }
        None
    }

    unsafe fn load_nvml_api() -> Option<NvmlApi> {
        let lib = [
            "libnvidia-ml.so.1",
            "libnvidia-ml.so",
            "/usr/lib/aarch64-linux-gnu/libnvidia-ml.so.1",
            "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
        ]
        .into_iter()
        .find_map(|path| unsafe { libloading::Library::new(path).ok() })?;
        let lib = Box::leak(Box::new(lib));

        Some(NvmlApi {
            init: unsafe { load_symbol(lib, &[b"nvmlInit_v2\0", b"nvmlInit\0"]) }?,
            shutdown: unsafe { load_symbol(lib, &[b"nvmlShutdown\0"]) }?,
            count: unsafe {
                load_symbol(lib, &[b"nvmlDeviceGetCount_v2\0", b"nvmlDeviceGetCount\0"])
            }?,
            handle: unsafe {
                load_symbol(
                    lib,
                    &[
                        b"nvmlDeviceGetHandleByIndex_v2\0",
                        b"nvmlDeviceGetHandleByIndex\0",
                    ],
                )
            }?,
            name: unsafe { load_symbol(lib, &[b"nvmlDeviceGetName\0"]) },
            util: unsafe { load_symbol(lib, &[b"nvmlDeviceGetUtilizationRates\0"]) },
            temp: unsafe { load_symbol(lib, &[b"nvmlDeviceGetTemperature\0"]) },
            power: unsafe { load_symbol(lib, &[b"nvmlDeviceGetPowerUsage\0"]) },
            clock: unsafe { load_symbol(lib, &[b"nvmlDeviceGetClockInfo\0"]) },
            memory: unsafe { load_symbol(lib, &[b"nvmlDeviceGetMemoryInfo\0"]) },
            fan: unsafe { load_symbol(lib, &[b"nvmlDeviceGetFanSpeed\0"]) },
            encoder: unsafe { load_symbol(lib, &[b"nvmlDeviceGetEncoderUtilization\0"]) },
            decoder: unsafe { load_symbol(lib, &[b"nvmlDeviceGetDecoderUtilization\0"]) },
        })
    }

    let Some(api) = nvml_api() else {
        return Vec::new();
    };

    unsafe {
        if (api.init)() != NVML_SUCCESS {
            return Vec::new();
        }

        let mut count: c_uint = 0;
        if (api.count)(&mut count as *mut c_uint) != NVML_SUCCESS {
            let _ = (api.shutdown)();
            return Vec::new();
        }

        let mut out = Vec::new();
        let device_count = count.min(max_devices as c_uint);
        for idx in 0..device_count {
            let mut device: NvmlDevice = std::ptr::null_mut();
            if (api.handle)(idx, &mut device as *mut NvmlDevice) != NVML_SUCCESS {
                continue;
            }

            let name = api.name.and_then(|name_fn| {
                let mut buf = [0 as c_char; 96];
                if name_fn(device, buf.as_mut_ptr(), buf.len() as c_uint) == NVML_SUCCESS {
                    let cstr = CStr::from_ptr(buf.as_ptr());
                    cstr.to_str().ok().map(|value| value.to_string())
                } else {
                    None
                }
            });

            let util_percent = api.util.and_then(|util_fn| {
                let mut util = NvmlUtilization { gpu: 0, memory: 0 };
                if util_fn(device, &mut util as *mut NvmlUtilization) == NVML_SUCCESS {
                    Some(util.gpu as f64)
                } else {
                    None
                }
            });

            let temp_c = api.temp.and_then(|temp_fn| {
                let mut temp = 0u32;
                if temp_fn(device, NVML_TEMPERATURE_GPU, &mut temp as *mut c_uint) == NVML_SUCCESS {
                    Some(temp as f64)
                } else {
                    None
                }
            });

            let (mem_total_bytes, mem_used_bytes) = api.memory.map_or((None, None), |mem_fn| {
                let mut mem = NvmlMemory {
                    total: 0,
                    free: 0,
                    used: 0,
                };
                if mem_fn(device, &mut mem as *mut NvmlMemory) == NVML_SUCCESS {
                    (Some(mem.total), Some(mem.used))
                } else {
                    (None, None)
                }
            });

            let power_w = api.power.and_then(|power_fn| {
                let mut power_mw = 0u32;
                if power_fn(device, &mut power_mw as *mut c_uint) == NVML_SUCCESS {
                    Some(power_mw as f64 / 1000.0)
                } else {
                    None
                }
            });

            let graphics_clock_mhz = api.clock.and_then(|clock_fn| {
                let mut value = 0u32;
                if clock_fn(device, NVML_CLOCK_GRAPHICS, &mut value as *mut c_uint) == NVML_SUCCESS
                {
                    Some(value as u64)
                } else {
                    None
                }
            });

            let memory_clock_mhz = api.clock.and_then(|clock_fn| {
                let mut value = 0u32;
                if clock_fn(device, NVML_CLOCK_MEM, &mut value as *mut c_uint) == NVML_SUCCESS {
                    Some(value as u64)
                } else {
                    None
                }
            });

            let fan_speed_percent = api.fan.and_then(|fan_fn| {
                let mut value = 0u32;
                if fan_fn(device, &mut value as *mut c_uint) == NVML_SUCCESS {
                    Some(value)
                } else {
                    None
                }
            });

            let encoder_util_percent = api.encoder.and_then(|codec_fn| {
                let mut value = 0u32;
                let mut period = 0u32;
                if codec_fn(
                    device,
                    &mut value as *mut c_uint,
                    &mut period as *mut c_uint,
                ) == NVML_SUCCESS
                {
                    Some(value)
                } else {
                    None
                }
            });

            let decoder_util_percent = api.decoder.and_then(|codec_fn| {
                let mut value = 0u32;
                let mut period = 0u32;
                if codec_fn(
                    device,
                    &mut value as *mut c_uint,
                    &mut period as *mut c_uint,
                ) == NVML_SUCCESS
                {
                    Some(value)
                } else {
                    None
                }
            });

            out.push(GpuSample {
                id: format!("nvidia:{}", idx),
                name,
                vendor: "nvidia".to_string(),
                source: "nvml".to_string(),
                util_percent,
                mem_used_bytes,
                mem_total_bytes,
                temp_c,
                power_w,
                graphics_clock_mhz,
                memory_clock_mhz,
                fan_speed_percent,
                encoder_util_percent,
                decoder_util_percent,
            });
        }

        let _ = (api.shutdown)();
        out
    }
}

#[cfg(not(target_os = "linux"))]
fn nvml_samples_sync(_max_devices: usize) -> Vec<GpuSample> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn rocm_samples_sync(max_devices: usize) -> Vec<GpuSample> {
    use std::ffi::CStr;
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

    struct RsmiApi {
        init: RsmiInit,
        shutdown: RsmiShutdown,
        count: RsmiGetCount,
        name: Option<RsmiGetName>,
        util: Option<RsmiGetUtil>,
        temp: Option<RsmiGetTemp>,
        mem_total: Option<RsmiGetMemTotal>,
        mem_used: Option<RsmiGetMemUsage>,
    }

    fn rsmi_api() -> Option<&'static RsmiApi> {
        static API: OnceLock<Option<RsmiApi>> = OnceLock::new();
        API.get_or_init(|| unsafe { load_rsmi_api() }).as_ref()
    }

    unsafe fn load_symbol<T: Copy>(lib: &libloading::Library, names: &[&[u8]]) -> Option<T> {
        for name in names {
            if let Ok(symbol) = unsafe { lib.get::<T>(name) } {
                return Some(*symbol);
            }
        }
        None
    }

    unsafe fn load_rsmi_api() -> Option<RsmiApi> {
        let lib = [
            "librocm_smi64.so.6",
            "librocm_smi64.so.5",
            "librocm_smi64.so",
        ]
        .into_iter()
        .find_map(|path| unsafe { libloading::Library::new(path).ok() })?;
        let lib = Box::leak(Box::new(lib));

        Some(RsmiApi {
            init: unsafe { load_symbol(lib, &[b"rsmi_init\0"]) }?,
            shutdown: unsafe { load_symbol(lib, &[b"rsmi_shut_down\0"]) }?,
            count: unsafe { load_symbol(lib, &[b"rsmi_num_monitor_devices\0"]) }?,
            name: unsafe { load_symbol(lib, &[b"rsmi_dev_name_get\0"]) },
            util: unsafe { load_symbol(lib, &[b"rsmi_dev_busy_percent_get\0"]) },
            temp: unsafe { load_symbol(lib, &[b"rsmi_dev_temp_metric_get\0"]) },
            mem_total: unsafe { load_symbol(lib, &[b"rsmi_dev_memory_total_get\0"]) },
            mem_used: unsafe { load_symbol(lib, &[b"rsmi_dev_memory_usage_get\0"]) },
        })
    }

    let Some(api) = rsmi_api() else {
        return Vec::new();
    };

    unsafe {
        if (api.init)(0) != RSMI_SUCCESS {
            return Vec::new();
        }

        let mut count: c_uint = 0;
        if (api.count)(&mut count as *mut c_uint) != RSMI_SUCCESS {
            let _ = (api.shutdown)();
            return Vec::new();
        }

        let mut out = Vec::new();
        let device_count = count.min(max_devices as c_uint);
        for idx in 0..device_count {
            let name = api.name.and_then(|name_fn| {
                let mut buf = [0 as c_char; 96];
                if name_fn(idx, buf.as_mut_ptr(), buf.len()) == RSMI_SUCCESS {
                    let cstr = CStr::from_ptr(buf.as_ptr());
                    cstr.to_str().ok().map(|value| value.to_string())
                } else {
                    None
                }
            });

            let util_percent = api.util.and_then(|util_fn| {
                let mut util = 0u32;
                if util_fn(idx, &mut util as *mut c_uint) == RSMI_SUCCESS {
                    Some(util as f64)
                } else {
                    None
                }
            });

            let temp_c = api.temp.and_then(|temp_fn| {
                let mut temp = 0i64;
                if temp_fn(
                    idx,
                    RSMI_TEMP_TYPE_EDGE,
                    RSMI_TEMP_CURRENT,
                    &mut temp as *mut i64,
                ) == RSMI_SUCCESS
                {
                    Some(if temp > 1000 {
                        temp as f64 / 1000.0
                    } else {
                        temp as f64
                    })
                } else {
                    None
                }
            });

            let mem_total_bytes = api.mem_total.and_then(|mem_total_fn| {
                let mut total = 0u64;
                if mem_total_fn(idx, RSMI_MEM_TYPE_VRAM, &mut total as *mut u64) == RSMI_SUCCESS {
                    Some(total)
                } else {
                    None
                }
            });

            let mem_used_bytes = api.mem_used.and_then(|mem_used_fn| {
                let mut used = 0u64;
                if mem_used_fn(idx, RSMI_MEM_TYPE_VRAM, &mut used as *mut u64) == RSMI_SUCCESS {
                    Some(used)
                } else {
                    None
                }
            });

            out.push(GpuSample {
                id: format!("amd:{}", idx),
                name,
                vendor: "amd".to_string(),
                source: "rocm_smi".to_string(),
                util_percent,
                mem_used_bytes,
                mem_total_bytes,
                temp_c,
                power_w: None,
                graphics_clock_mhz: None,
                memory_clock_mhz: None,
                fan_speed_percent: None,
                encoder_util_percent: None,
                decoder_util_percent: None,
            });
        }

        let _ = (api.shutdown)();
        out
    }
}

#[cfg(not(target_os = "linux"))]
fn rocm_samples_sync(_max_devices: usize) -> Vec<GpuSample> {
    Vec::new()
}

async fn read_trimmed(path: PathBuf) -> Option<String> {
    let raw = fs::read_to_string(path).await.ok()?;
    let value = raw.trim_matches(|ch: char| ch.is_whitespace() || ch == '\0');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

async fn read_u64<P: AsRef<Path>>(path: P) -> Option<u64> {
    read_i64(path)
        .await
        .and_then(|value| if value >= 0 { Some(value as u64) } else { None })
}

async fn read_i64<P: AsRef<Path>>(path: P) -> Option<i64> {
    let raw = fs::read_to_string(path).await.ok()?;
    raw.trim().parse::<i64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_backend_config_honors_gpu_switches() {
        let mut config = EmbeddedConfig::default();
        config.gpu_enabled = true;
        config.gpu_nvml_enabled = true;
        config.gpu_rocm_enabled = false;
        config.gpu_sysfs_enabled = true;
        config.gpu_max_devices = 3;

        let backend = GpuBackendConfig::from(&config);
        assert!(backend.any_enabled());
        assert!(backend.nvml_enabled);
        assert!(backend.sysfs_enabled);
        assert!(!backend.rocm_enabled);
        assert_eq!(backend.max_devices, 3);
    }

    #[test]
    fn embedded_backend_config_disables_all_backends_when_gpu_is_disabled() {
        let mut config = EmbeddedConfig::default();
        config.gpu_enabled = false;
        let backend = GpuBackendConfig::from(&config);
        assert!(!backend.any_enabled());
    }

    #[test]
    fn tracey_guard_backend_config_keeps_backend_preferences_when_embedded_is_disabled() {
        let mut config = EmbeddedConfig::default();
        config.gpu_enabled = false;
        config.gpu_nvml_enabled = true;
        config.gpu_rocm_enabled = false;
        config.gpu_sysfs_enabled = true;

        let backend = GpuBackendConfig::from_embedded_with_limit(&config, 5);
        assert!(backend.nvml_enabled);
        assert!(backend.sysfs_enabled);
        assert!(!backend.rocm_enabled);
        assert_eq!(backend.max_devices, 5);
    }

    #[test]
    fn vendor_mapping_is_stable() {
        assert_eq!(vendor_from_id(Some("0x10de")), "nvidia");
        assert_eq!(vendor_from_id(Some("0x1002")), "amd");
        assert_eq!(vendor_from_id(Some("0x8086")), "intel");
        assert_eq!(vendor_from_id(Some("0x0000")), "unknown");
        assert_eq!(vendor_from_id(None), "unknown");
    }
}
