use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub os: String,
    pub arch: String,
    pub cpu_cores: usize,
    pub tags: Vec<String>,
}

impl Capabilities {
    pub fn local() -> Self {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        let cpu_cores = num_cpus::get();
        let mut tags = Vec::new();
        if os == "linux" {
            tags.extend(linux_device_tree_tags());
        }
        Self {
            os,
            arch,
            cpu_cores,
            tags: dedup_tags(tags),
        }
    }
}

fn linux_device_tree_tags() -> Vec<String> {
    let mut tags = Vec::new();
    let model = read_dt_string("/sys/firmware/devicetree/base/model")
        .or_else(|| read_dt_string("/proc/device-tree/model"));
    if let Some(model) = model {
        if let Some(tag) = tag_with_prefix("board", &model) {
            tags.push(tag);
        }
    }

    let compat = read_dt_strings("/sys/firmware/devicetree/base/compatible")
        .or_else(|| read_dt_strings("/proc/device-tree/compatible"))
        .unwrap_or_default();
    if let Some(primary) = compat.first() {
        if let Some(tag) = tag_with_prefix("soc", primary) {
            tags.push(tag);
        }
    }
    if compat
        .iter()
        .any(|item| item.to_lowercase().contains("nvidia") || item.to_lowercase().contains("tegra"))
    {
        tags.push("vendor:nvidia".to_string());
        tags.push("jetson".to_string());
    }

    tags
}

fn read_dt_string(path: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let raw = bytes.split(|b| *b == 0).next().unwrap_or_default();
    let value = String::from_utf8_lossy(raw).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn read_dt_strings(path: &str) -> Option<Vec<String>> {
    let bytes = std::fs::read(path).ok()?;
    let mut out = Vec::new();
    let mut start = 0usize;
    for (idx, b) in bytes.iter().enumerate() {
        if *b == 0 {
            if idx > start {
                let value = String::from_utf8_lossy(&bytes[start..idx]).trim().to_string();
                if !value.is_empty() {
                    out.push(value);
                }
            }
            start = idx + 1;
        }
    }
    if start < bytes.len() {
        let value = String::from_utf8_lossy(&bytes[start..]).trim().to_string();
        if !value.is_empty() {
            out.push(value);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn tag_with_prefix(prefix: &str, value: &str) -> Option<String> {
    let normalized = normalize_tag_value(value);
    if normalized.is_empty() {
        None
    } else {
        Some(format!("{}:{}", prefix, normalized))
    }
}

fn normalize_tag_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else if ch == ' ' || ch == ',' || ch == '.' || ch == '/' {
            out.push('_');
        }
    }
    if out.len() > 64 {
        out.truncate(64);
    }
    out.trim_matches('_').to_string()
}

fn dedup_tags(tags: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for tag in tags {
        if tag.is_empty() {
            continue;
        }
        if seen.insert(tag.clone()) {
            out.push(tag);
        }
    }
    out
}
