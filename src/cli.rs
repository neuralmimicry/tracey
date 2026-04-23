//! Lightweight operator CLI for local Tracey control and status access.

use crate::config::Config;
use serde_json::{Value, json};
use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
struct CliHttpOptions {
    addr: Option<String>,
    token: Option<String>,
    json: bool,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuntimeStartOptions {
    pub ebpf_mode: Option<String>,
}

#[derive(Debug, Clone)]
enum ParsedCliCommand {
    Help,
    Status(CliHttpOptions),
    TraceyBanStatus(CliHttpOptions),
    TraceyGuardStatus(CliHttpOptions),
    TraceyBanBan {
        http: CliHttpOptions,
        jail: String,
        ip: String,
        reason: Option<String>,
        source: Option<String>,
        ban_time_ms: Option<u64>,
    },
    TraceyBanUnban {
        http: CliHttpOptions,
        jail: String,
        ip: String,
        reason: Option<String>,
        source: Option<String>,
    },
    TraceyBanRefreshBackend {
        http: CliHttpOptions,
        jail: Option<String>,
    },
    TraceyBanFilters {
        json: bool,
    },
    TraceyBanActions {
        json: bool,
    },
    TraceyGuardEnable(CliHttpOptions),
    TraceyGuardDisable(CliHttpOptions),
    TraceyGuardDeepDive {
        http: CliHttpOptions,
        enabled: bool,
    },
    TraceyGuardTmr {
        http: CliHttpOptions,
        enabled: bool,
    },
    TraceyGuardSetOverhead {
        http: CliHttpOptions,
        pct: f64,
    },
    TraceyGuardSetParallelism {
        http: CliHttpOptions,
        count: usize,
    },
    TraceyGuardForceScan(CliHttpOptions),
}

struct CliArgCursor<'a> {
    args: &'a [String],
    idx: usize,
}

impl<'a> CliArgCursor<'a> {
    fn new(args: &'a [String]) -> Self {
        Self { args, idx: 0 }
    }

    fn next(&mut self) -> Option<&'a str> {
        let value = self.args.get(self.idx)?;
        self.idx += 1;
        Some(value.as_str())
    }

    fn value(&mut self, flag: &str) -> Result<String, String> {
        self.next()
            .map(ToString::to_string)
            .ok_or_else(|| format!("missing value for {}", flag))
    }
}

pub async fn maybe_run_cli(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let Some(command) = parse_cli_command(args)? else {
        return Ok(false);
    };
    run_cli_command(command).await?;
    Ok(true)
}

pub(crate) fn parse_runtime_start_options(
    args: &[String],
) -> Result<RuntimeStartOptions, Box<dyn Error>> {
    let mut cursor = CliArgCursor::new(args.get(1..).unwrap_or(&[]));
    let mut options = RuntimeStartOptions::default();
    while let Some(flag) = cursor.next() {
        if let Some(value) = flag.strip_prefix("--ebpf=") {
            options.ebpf_mode = Some(parse_ebpf_mode(value)?);
            continue;
        }
        if flag == "--ebpf" {
            options.ebpf_mode = Some(parse_ebpf_mode(&cursor.value(flag)?)?);
        }
    }
    Ok(options)
}

fn parse_cli_command(args: &[String]) -> Result<Option<ParsedCliCommand>, Box<dyn Error>> {
    let Some(command) = args.get(1).map(String::as_str) else {
        return Ok(None);
    };

    let parsed = match command {
        "help" | "--help" | "-h" => ParsedCliCommand::Help,
        "status" => ParsedCliCommand::Status(parse_status_options(&args[2..])?),
        "tracey-ban" | "tracey_ban" => parse_tracey_ban_command(&args[2..])?,
        "tracey-guard" | "tracey_guard" => parse_tracey_guard_command(&args[2..])?,
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

fn parse_status_options(args: &[String]) -> Result<CliHttpOptions, Box<dyn Error>> {
    let mut cursor = CliArgCursor::new(args);
    let mut options = CliHttpOptions::default();
    while let Some(flag) = cursor.next() {
        if consume_http_option(flag, &mut cursor, &mut options)? {
            continue;
        }
        return Err(invalid_cli_usage(format!(
            "unsupported status option {}",
            flag
        )));
    }
    Ok(options)
}

fn parse_tracey_ban_command(args: &[String]) -> Result<ParsedCliCommand, Box<dyn Error>> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Ok(ParsedCliCommand::Help);
    };

    match subcommand {
        "help" | "--help" | "-h" => Ok(ParsedCliCommand::Help),
        "status" => Ok(ParsedCliCommand::TraceyBanStatus(parse_status_options(
            &args[1..],
        )?)),
        "filters" => Ok(ParsedCliCommand::TraceyBanFilters {
            json: parse_json_flag(&args[1..])?,
        }),
        "actions" => Ok(ParsedCliCommand::TraceyBanActions {
            json: parse_json_flag(&args[1..])?,
        }),
        "refresh-backend" => parse_tracey_ban_refresh(&args[1..]),
        "ban" => parse_tracey_ban_ban(&args[1..]),
        "unban" => parse_tracey_ban_unban(&args[1..]),
        other => Err(invalid_cli_usage(format!(
            "unsupported tracey-ban subcommand {}",
            other
        ))),
    }
}

fn parse_tracey_guard_command(args: &[String]) -> Result<ParsedCliCommand, Box<dyn Error>> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Ok(ParsedCliCommand::Help);
    };

    match subcommand {
        "help" | "--help" | "-h" => Ok(ParsedCliCommand::Help),
        "status" => Ok(ParsedCliCommand::TraceyGuardStatus(parse_status_options(
            &args[1..],
        )?)),
        "enable" => Ok(ParsedCliCommand::TraceyGuardEnable(parse_status_options(
            &args[1..],
        )?)),
        "disable" => Ok(ParsedCliCommand::TraceyGuardDisable(parse_status_options(
            &args[1..],
        )?)),
        "deep-dive" | "deep_dive" => {
            parse_tracey_guard_toggle(&args[1..], "deep-dive", |http, enabled| {
                ParsedCliCommand::TraceyGuardDeepDive { http, enabled }
            })
        }
        "tmr" => parse_tracey_guard_toggle(&args[1..], "tmr", |http, enabled| {
            ParsedCliCommand::TraceyGuardTmr { http, enabled }
        }),
        "set-overhead" | "set_overhead" => parse_tracey_guard_set_overhead(&args[1..]),
        "set-parallelism" | "set_parallelism" => parse_tracey_guard_set_parallelism(&args[1..]),
        "force-scan" | "force_scan" => Ok(ParsedCliCommand::TraceyGuardForceScan(
            parse_status_options(&args[1..])?,
        )),
        other => Err(invalid_cli_usage(format!(
            "unsupported tracey-guard subcommand {}",
            other
        ))),
    }
}

fn parse_tracey_ban_refresh(args: &[String]) -> Result<ParsedCliCommand, Box<dyn Error>> {
    let mut cursor = CliArgCursor::new(args);
    let mut http = CliHttpOptions::default();
    let mut jail = None;
    while let Some(flag) = cursor.next() {
        if consume_http_option(flag, &mut cursor, &mut http)? {
            continue;
        }
        match flag {
            "--jail" => jail = Some(cursor.value(flag)?),
            _ => {
                return Err(invalid_cli_usage(format!(
                    "unsupported refresh-backend option {}",
                    flag
                )));
            }
        }
    }
    Ok(ParsedCliCommand::TraceyBanRefreshBackend { http, jail })
}

fn parse_tracey_ban_ban(args: &[String]) -> Result<ParsedCliCommand, Box<dyn Error>> {
    let mut cursor = CliArgCursor::new(args);
    let mut http = CliHttpOptions::default();
    let mut jail = None;
    let mut ip = None;
    let mut reason = None;
    let mut source = None;
    let mut ban_time_ms = None;

    while let Some(flag) = cursor.next() {
        if consume_http_option(flag, &mut cursor, &mut http)? {
            continue;
        }
        match flag {
            "--jail" => jail = Some(cursor.value(flag)?),
            "--ip" => ip = Some(cursor.value(flag)?),
            "--reason" => reason = Some(cursor.value(flag)?),
            "--source" => source = Some(cursor.value(flag)?),
            "--ban-time-ms" => {
                ban_time_ms = Some(parse_u64_flag(&cursor.value(flag)?, flag)?);
            }
            _ => {
                return Err(invalid_cli_usage(format!(
                    "unsupported ban option {}",
                    flag
                )));
            }
        }
    }

    Ok(ParsedCliCommand::TraceyBanBan {
        http,
        jail: jail.ok_or_else(|| invalid_cli_usage("missing required --jail".to_string()))?,
        ip: ip.ok_or_else(|| invalid_cli_usage("missing required --ip".to_string()))?,
        reason,
        source,
        ban_time_ms,
    })
}

fn parse_tracey_ban_unban(args: &[String]) -> Result<ParsedCliCommand, Box<dyn Error>> {
    let mut cursor = CliArgCursor::new(args);
    let mut http = CliHttpOptions::default();
    let mut jail = None;
    let mut ip = None;
    let mut reason = None;
    let mut source = None;

    while let Some(flag) = cursor.next() {
        if consume_http_option(flag, &mut cursor, &mut http)? {
            continue;
        }
        match flag {
            "--jail" => jail = Some(cursor.value(flag)?),
            "--ip" => ip = Some(cursor.value(flag)?),
            "--reason" => reason = Some(cursor.value(flag)?),
            "--source" => source = Some(cursor.value(flag)?),
            _ => {
                return Err(invalid_cli_usage(format!(
                    "unsupported unban option {}",
                    flag
                )));
            }
        }
    }

    Ok(ParsedCliCommand::TraceyBanUnban {
        http,
        jail: jail.ok_or_else(|| invalid_cli_usage("missing required --jail".to_string()))?,
        ip: ip.ok_or_else(|| invalid_cli_usage("missing required --ip".to_string()))?,
        reason,
        source,
    })
}

fn parse_tracey_guard_toggle<F>(
    args: &[String],
    subject: &str,
    build: F,
) -> Result<ParsedCliCommand, Box<dyn Error>>
where
    F: FnOnce(CliHttpOptions, bool) -> ParsedCliCommand,
{
    let mut cursor = CliArgCursor::new(args);
    let raw_state = cursor
        .next()
        .ok_or_else(|| invalid_cli_usage(format!("missing required state for {}", subject)))?;
    let enabled = parse_toggle_state(raw_state, subject)?;
    let mut http = CliHttpOptions::default();
    while let Some(flag) = cursor.next() {
        if consume_http_option(flag, &mut cursor, &mut http)? {
            continue;
        }
        return Err(invalid_cli_usage(format!(
            "unsupported {} option {}",
            subject, flag
        )));
    }
    Ok(build(http, enabled))
}

fn parse_tracey_guard_set_overhead(args: &[String]) -> Result<ParsedCliCommand, Box<dyn Error>> {
    let mut cursor = CliArgCursor::new(args);
    let mut http = CliHttpOptions::default();
    let mut pct = None;
    while let Some(flag) = cursor.next() {
        if consume_http_option(flag, &mut cursor, &mut http)? {
            continue;
        }
        match flag {
            "--pct" => pct = Some(parse_f64_flag(&cursor.value(flag)?, flag)?),
            _ => {
                return Err(invalid_cli_usage(format!(
                    "unsupported set-overhead option {}",
                    flag
                )));
            }
        }
    }

    Ok(ParsedCliCommand::TraceyGuardSetOverhead {
        http,
        pct: pct.ok_or_else(|| invalid_cli_usage("missing required --pct".to_string()))?,
    })
}

fn parse_tracey_guard_set_parallelism(args: &[String]) -> Result<ParsedCliCommand, Box<dyn Error>> {
    let mut cursor = CliArgCursor::new(args);
    let mut http = CliHttpOptions::default();
    let mut count = None;
    while let Some(flag) = cursor.next() {
        if consume_http_option(flag, &mut cursor, &mut http)? {
            continue;
        }
        match flag {
            "--count" => count = Some(parse_usize_flag(&cursor.value(flag)?, flag)?),
            _ => {
                return Err(invalid_cli_usage(format!(
                    "unsupported set-parallelism option {}",
                    flag
                )));
            }
        }
    }

    Ok(ParsedCliCommand::TraceyGuardSetParallelism {
        http,
        count: count.ok_or_else(|| invalid_cli_usage("missing required --count".to_string()))?,
    })
}

fn parse_json_flag(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let mut cursor = CliArgCursor::new(args);
    let mut json = false;
    while let Some(flag) = cursor.next() {
        match flag {
            "--json" => json = true,
            _ => {
                return Err(invalid_cli_usage(format!("unsupported option {}", flag)));
            }
        }
    }
    Ok(json)
}

fn parse_ebpf_mode(value: &str) -> Result<String, Box<dyn Error>> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "disabled" | "auto" | "required" => Ok(normalized),
        _ => Err(invalid_cli_usage(format!(
            "invalid value for --ebpf: {} (expected disabled, auto, or required)",
            value
        ))),
    }
}

fn consume_http_option(
    flag: &str,
    cursor: &mut CliArgCursor<'_>,
    options: &mut CliHttpOptions,
) -> Result<bool, Box<dyn Error>> {
    match flag {
        "--addr" => {
            options.addr = Some(cursor.value(flag)?);
            Ok(true)
        }
        "--token" => {
            options.token = Some(cursor.value(flag)?);
            Ok(true)
        }
        "--timeout-ms" => {
            options.timeout_ms = Some(parse_u64_flag(&cursor.value(flag)?, flag)?);
            Ok(true)
        }
        "--json" => {
            options.json = true;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn parse_u64_flag(raw: &str, flag: &str) -> Result<u64, Box<dyn Error>> {
    raw.parse::<u64>()
        .map_err(|err| invalid_cli_usage(format!("invalid value for {}: {}", flag, err)))
}

fn parse_usize_flag(raw: &str, flag: &str) -> Result<usize, Box<dyn Error>> {
    raw.parse::<usize>()
        .map_err(|err| invalid_cli_usage(format!("invalid value for {}: {}", flag, err)))
}

fn parse_f64_flag(raw: &str, flag: &str) -> Result<f64, Box<dyn Error>> {
    raw.parse::<f64>()
        .map_err(|err| invalid_cli_usage(format!("invalid value for {}: {}", flag, err)))
}

fn parse_toggle_state(raw: &str, subject: &str) -> Result<bool, Box<dyn Error>> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "on" | "enable" | "enabled" | "true" | "1" => Ok(true),
        "off" | "disable" | "disabled" | "false" | "0" => Ok(false),
        _ => Err(invalid_cli_usage(format!(
            "invalid state for {}: expected on/off",
            subject
        ))),
    }
}

async fn run_cli_command(command: ParsedCliCommand) -> Result<(), Box<dyn Error>> {
    match command {
        ParsedCliCommand::Help => {
            print_help();
            Ok(())
        }
        ParsedCliCommand::Status(http) => {
            let config = Config::load();
            let response = request_json(&config, &http, "/status", None).await?;
            print_status_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyBanStatus(http) => {
            let config = Config::load();
            let response = request_json(&config, &http, "/tracey_ban", None).await?;
            print_tracey_ban_status_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyGuardStatus(http) => {
            let config = Config::load();
            let response = request_json(&config, &http, "/tracey_guard", None).await?;
            print_tracey_guard_status_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyBanBan {
            http,
            jail,
            ip,
            reason,
            source,
            ban_time_ms,
        } => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_ban",
                Some(json!({
                    "operation": "ban",
                    "jail": jail,
                    "ip": ip,
                    "reason": reason,
                    "source": source,
                    "ban_time_ms": ban_time_ms,
                })),
            )
            .await?;
            print_tracey_ban_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyBanUnban {
            http,
            jail,
            ip,
            reason,
            source,
        } => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_ban",
                Some(json!({
                    "operation": "unban",
                    "jail": jail,
                    "ip": ip,
                    "reason": reason,
                    "source": source,
                })),
            )
            .await?;
            print_tracey_ban_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyBanRefreshBackend { http, jail } => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_ban",
                Some(json!({
                    "operation": "refresh_backend",
                    "jail": jail,
                })),
            )
            .await?;
            print_tracey_ban_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyBanFilters { json } => {
            let catalogs = crate::tracey_ban::built_in_filter_catalog_summaries();
            if json {
                println!("{}", serde_json::to_string_pretty(&catalogs)?);
            } else {
                for entry in catalogs {
                    println!("{}: {}", entry.name, entry.description);
                    if !entry.log_paths.is_empty() {
                        println!("  logs: {}", entry.log_paths.join(", "));
                    }
                    if !entry.journal_matches.is_empty() {
                        println!("  journal: {}", entry.journal_matches.join(" | "));
                    }
                    if !entry.ports.is_empty() {
                        println!(
                            "  ports: {}/{}",
                            entry
                                .ports
                                .iter()
                                .map(|port| port.to_string())
                                .collect::<Vec<_>>()
                                .join(","),
                            entry.protocol
                        );
                    }
                }
            }
            Ok(())
        }
        ParsedCliCommand::TraceyBanActions { json } => {
            let actions = crate::tracey_ban::built_in_action_catalog_summaries();
            if json {
                println!("{}", serde_json::to_string_pretty(&actions)?);
            } else {
                for entry in actions {
                    println!("{}: {}", entry.name, entry.description);
                }
            }
            Ok(())
        }
        ParsedCliCommand::TraceyGuardEnable(http) => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_guard",
                Some(json!({ "enabled": true })),
            )
            .await?;
            print_tracey_guard_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyGuardDisable(http) => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_guard",
                Some(json!({ "enabled": false })),
            )
            .await?;
            print_tracey_guard_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyGuardDeepDive { http, enabled } => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_guard",
                Some(json!({ "deep_dive": enabled })),
            )
            .await?;
            print_tracey_guard_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyGuardTmr { http, enabled } => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_guard",
                Some(json!({ "tmr_enabled": enabled })),
            )
            .await?;
            print_tracey_guard_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyGuardSetOverhead { http, pct } => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_guard",
                Some(json!({ "overhead_budget_pct": pct })),
            )
            .await?;
            print_tracey_guard_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyGuardSetParallelism { http, count } => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_guard",
                Some(json!({ "max_parallel_tasks": count })),
            )
            .await?;
            print_tracey_guard_control_output(&response, http.json)?;
            Ok(())
        }
        ParsedCliCommand::TraceyGuardForceScan(http) => {
            let config = Config::load();
            let response = request_json(
                &config,
                &http,
                "/control/tracey_guard",
                Some(json!({ "force_scan": true })),
            )
            .await?;
            print_tracey_guard_control_output(&response, http.json)?;
            Ok(())
        }
    }
}

async fn request_json(
    config: &Config,
    http: &CliHttpOptions,
    endpoint: &str,
    body: Option<Value>,
) -> Result<Value, Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            http.timeout_ms
                .unwrap_or(config.status.proxy_timeout_ms.max(500)),
        ))
        .build()?;
    let url = status_endpoint_url(resolve_status_base(config, http.addr.as_deref())?, endpoint)?;
    let mut request = if let Some(body) = body {
        client.post(url).json(&body)
    } else {
        client.get(url)
    };
    if let Some(token) = http
        .token
        .clone()
        .or_else(|| std::env::var("TRACEY_STATUS_TOKEN").ok())
        .or_else(|| std::env::var("TRACEY_AUTH_BEARER").ok())
        .filter(|value| !value.trim().is_empty())
    {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        let preview = truncate_preview(&text, 512);
        return Err(
            std::io::Error::other(format!("{} {} failed: {}", status, endpoint, preview)).into(),
        );
    }
    Ok(serde_json::from_str::<Value>(&text)?)
}

fn resolve_status_base(
    config: &Config,
    override_addr: Option<&str>,
) -> Result<reqwest::Url, Box<dyn Error>> {
    let raw = override_addr
        .map(ToString::to_string)
        .or_else(|| std::env::var("TRACEY_STATUS_ADDR").ok())
        .or_else(|| config.status.public_addr.clone())
        .or_else(|| {
            if config.status.listen_addr.trim().is_empty() {
                None
            } else {
                Some(config.status.listen_addr.clone())
            }
        })
        .ok_or_else(|| {
            std::io::Error::other(
                "could not resolve Tracey status address; pass --addr or set TRACEY_STATUS_ADDR",
            )
        })?;

    normalize_status_base(&raw).map_err(|err| {
        std::io::Error::other(format!("invalid status address {}: {}", raw, err)).into()
    })
}

fn normalize_status_base(raw: &str) -> Result<reqwest::Url, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let (scheme, rest) =
        split_status_scheme(trimmed).unwrap_or((preferred_status_scheme(trimmed), trimmed));
    let rewritten = rewrite_unspecified_status_host(rest);
    let mut url =
        reqwest::Url::parse(&format!("{}{}", scheme, rewritten)).map_err(|err| err.to_string())?;
    let stripped = strip_known_status_endpoint(url.path());
    url.set_path(&stripped);
    Ok(url)
}

fn status_endpoint_url(
    mut base: reqwest::Url,
    endpoint: &str,
) -> Result<reqwest::Url, Box<dyn Error>> {
    let base_path = base.path().trim_end_matches('/');
    let endpoint = endpoint.trim_start_matches('/');
    let joined = if base_path.is_empty() || base_path == "/" {
        format!("/{}", endpoint)
    } else {
        format!("{}/{}", base_path, endpoint)
    };
    base.set_path(&joined);
    Ok(base)
}

fn strip_known_status_endpoint(path: &str) -> String {
    for suffix in [
        "/status",
        "/health",
        "/ready",
        "/tracey_ban",
        "/tracey_guard",
        "/control/tracey_ban",
        "/control/tracey_guard",
    ] {
        if path == suffix {
            return "/".to_string();
        }
        if let Some(prefix) = path.strip_suffix(suffix) {
            return if prefix.is_empty() {
                "/".to_string()
            } else {
                prefix.trim_end_matches('/').to_string()
            };
        }
    }
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn split_status_scheme(raw: &str) -> Option<(&'static str, &str)> {
    if let Some(value) = raw.strip_prefix("http://") {
        Some(("http://", value))
    } else if let Some(value) = raw.strip_prefix("https://") {
        Some(("https://", value))
    } else {
        None
    }
}

fn preferred_status_scheme(raw: &str) -> &'static str {
    if is_local_status_target(raw) {
        "http://"
    } else {
        "https://"
    }
}

fn is_local_status_target(raw: &str) -> bool {
    let authority = raw.split('/').next().unwrap_or(raw).trim();
    if authority.is_empty() {
        return false;
    }

    let host = status_authority_host(authority);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    let host = host.trim_matches('[').trim_matches(']');
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback() || ip.is_unspecified())
        .unwrap_or(false)
}

fn status_authority_host(authority: &str) -> &str {
    if let Some(host) = authority.strip_prefix('[') {
        return host.split(']').next().unwrap_or(host);
    }

    if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
        authority
    } else {
        authority.split(':').next().unwrap_or(authority)
    }
}

fn rewrite_unspecified_status_host(rest: &str) -> String {
    if let Some(port) = rest.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{port}")
    } else if rest == "0.0.0.0" {
        "127.0.0.1".to_string()
    } else if let Some(port) = rest.strip_prefix("[::]:") {
        format!("[::1]:{port}")
    } else if rest == "[::]" || rest == "::" {
        "[::1]".to_string()
    } else {
        rest.to_string()
    }
}

fn truncate_preview(raw: &str, max_chars: usize) -> String {
    let mut out = raw.replace('\n', " ").replace('\r', " ");
    if out.len() > max_chars {
        out.truncate(max_chars);
    }
    out
}

fn print_status_output(value: &Value, json_output: bool) -> Result<(), Box<dyn Error>> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }

    println!(
        "agent_id: {}",
        value
            .get("agent_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    if let Some(version) = value.get("agent_version").and_then(Value::as_str) {
        println!("version: {}", version);
    }
    if let Some(status) = value.get("status").and_then(Value::as_str) {
        println!("status: {}", status);
    }
    if let Some(posture) = value.get("posture").and_then(Value::as_str) {
        println!("posture: {}", posture);
    }
    println!(
        "coordinator: {}",
        value
            .get("is_coordinator")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    println!(
        "tracey_ban: local={} remote={} remote_agents={}",
        value
            .get("tracey_ban_local_bans")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        value
            .get("tracey_ban_remote_bans")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        value
            .get("tracey_ban_remote_agents")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );
    if let Some(summary) = value
        .get("tracey_guard")
        .and_then(|guard| guard.get("summary"))
        .filter(|summary| summary.is_object())
    {
        println!(
            "tracey_guard: enabled={} devices={} quarantined={} condemned={} executions={}",
            summary
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            summary
                .get("total_devices")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            summary
                .get("quarantined_devices")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            summary
                .get("condemned_devices")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            summary
                .get("total_executions")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        );
    }
    if let Some(addr) = value.get("status_addr").and_then(Value::as_str) {
        println!("status_addr: {}", addr);
    }
    Ok(())
}

fn print_tracey_ban_status_output(value: &Value, json_output: bool) -> Result<(), Box<dyn Error>> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }

    let summary = value.get("summary").unwrap_or(&Value::Null);
    println!(
        "enabled: {}",
        summary
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    println!(
        "jails: {} active_jails={}",
        summary
            .get("jail_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("active_jails")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );
    println!(
        "bans: local={} remote={} remote_agents={}",
        summary
            .get("local_ban_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("remote_ban_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("remote_agents")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );

    if let Some(jails) = value.get("jails").and_then(Value::as_array) {
        for jail in jails {
            println!(
                "{}: filter={} action={} backend={} -> {} active_bans={}",
                jail.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                jail.get("filter_catalog")
                    .and_then(Value::as_str)
                    .unwrap_or("-"),
                jail.get("action_catalog")
                    .and_then(Value::as_str)
                    .unwrap_or("-"),
                jail.get("firewall_backend")
                    .and_then(Value::as_str)
                    .unwrap_or("-"),
                jail.get("resolved_firewall_backend")
                    .and_then(Value::as_str)
                    .unwrap_or("-"),
                jail.get("active_bans").and_then(Value::as_u64).unwrap_or(0)
            );
        }
    }
    Ok(())
}

fn print_tracey_ban_control_output(value: &Value, json_output: bool) -> Result<(), Box<dyn Error>> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }

    let control = value.get("control").unwrap_or(value);
    println!(
        "{}: {}",
        control
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("control"),
        control
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("no message")
    );
    if let Some(targets) = control.get("targets").and_then(Value::as_array) {
        for target in targets {
            println!(
                "  jail={} ip={} backend={} active_bans={}",
                target
                    .get("jail")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                target.get("ip").and_then(Value::as_str).unwrap_or("-"),
                target
                    .get("resolved_firewall_backend")
                    .and_then(Value::as_str)
                    .unwrap_or("-"),
                target
                    .get("active_bans")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            );
        }
    }
    if let Some(summary) = value.get("summary") {
        println!(
            "summary: local={} remote={} jails={}",
            summary
                .get("local_ban_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            summary
                .get("remote_ban_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            summary
                .get("jail_count")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        );
    }
    Ok(())
}

fn print_tracey_guard_status_output(
    value: &Value,
    json_output: bool,
) -> Result<(), Box<dyn Error>> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }

    let control = value.get("control").unwrap_or(&Value::Null);
    let summary = value.get("summary").unwrap_or(&Value::Null);
    print_tracey_guard_control_state(control);
    print_tracey_guard_summary(summary);
    println!(
        "faults: local_recent={} remote_recent={} recent_executions={} timeline_buckets={}",
        value
            .get("recent_faults")
            .and_then(Value::as_array)
            .map(|entries| entries.len())
            .unwrap_or(0),
        value
            .get("remote_faults")
            .and_then(Value::as_array)
            .map(|entries| entries.len())
            .unwrap_or(0),
        value
            .get("recent_executions")
            .and_then(Value::as_array)
            .map(|entries| entries.len())
            .unwrap_or(0),
        value
            .get("timeline")
            .and_then(Value::as_array)
            .map(|entries| entries.len())
            .unwrap_or(0)
    );
    print_tracey_guard_probe_details(summary);
    print_tracey_guard_gpu_health(value);
    Ok(())
}

fn print_tracey_guard_control_output(
    value: &Value,
    json_output: bool,
) -> Result<(), Box<dyn Error>> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }

    let control = value.get("control").unwrap_or(&Value::Null);
    let summary = value.get("summary").unwrap_or(&Value::Null);
    print_tracey_guard_control_state(control);
    print_tracey_guard_summary(summary);
    if let Some(updated_ms) = value.get("updated_ms").and_then(Value::as_u64) {
        println!("updated_ms: {}", updated_ms);
    }
    Ok(())
}

fn print_tracey_guard_control_state(control: &Value) {
    println!(
        "enabled: {} deep_dive={} tmr={} overhead_budget_pct={:.2} max_parallel_tasks={} force_scan_epoch={}",
        control
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        control
            .get("deep_dive")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        control
            .get("tmr_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        control
            .get("overhead_budget_pct")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        control
            .get("max_parallel_tasks")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        control
            .get("force_scan_epoch")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );
}

fn print_tracey_guard_summary(summary: &Value) {
    println!(
        "scheduler: poll_ms={} target_poll_ms={} signal={:.3} scale={:.3}",
        summary
            .get("scheduler_poll_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("scheduler_target_poll_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("scheduler_signal")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        summary
            .get("scheduler_period_scale")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
    );
    println!(
        "devices: total={} healthy={} suspect={} quarantined={} deep_test={} condemned={}",
        summary
            .get("total_devices")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("healthy_devices")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("suspect_devices")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("quarantined_devices")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("deep_test_devices")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("condemned_devices")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );
    println!(
        "executions: total={} failures={} errors={} timeouts={} remote_fault_support={}",
        summary
            .get("total_executions")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("total_failures")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("total_errors")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("total_timeouts")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        summary
            .get("remote_fault_support")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );
}

fn print_tracey_guard_probe_details(summary: &Value) {
    let Some(probes) = summary.get("probes").and_then(Value::as_object) else {
        return;
    };
    let mut entries: Vec<_> = probes.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (name, counters) in entries {
        println!(
            "probe {}: exec={} pass={} fail={} error={} timeout={} avg_ms={:.1}",
            name,
            counters
                .get("executions")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            counters.get("pass").and_then(Value::as_u64).unwrap_or(0),
            counters.get("fail").and_then(Value::as_u64).unwrap_or(0),
            counters.get("error").and_then(Value::as_u64).unwrap_or(0),
            counters.get("timeout").and_then(Value::as_u64).unwrap_or(0),
            counters
                .get("avg_execution_ms")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
        );
    }
}

fn print_tracey_guard_gpu_health(value: &Value) {
    let Some(gpu_health) = value.get("gpu_health").and_then(Value::as_array) else {
        return;
    };
    for gpu in gpu_health {
        println!(
            "{}: state={} reliability={:.3} pass={} fail={} error={} consecutive_failures={} last_risk={:.3} last_confidence={:.3} reason={}",
            gpu.get("gpu_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            gpu.get("state")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            gpu.get("reliability_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
            gpu.get("probe_pass_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            gpu.get("probe_fail_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            gpu.get("probe_error_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            gpu.get("consecutive_failures")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            gpu.get("last_risk").and_then(Value::as_f64).unwrap_or(0.0),
            gpu.get("last_confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
            gpu.get("last_reason")
                .and_then(Value::as_str)
                .unwrap_or("-")
        );
    }
}

fn invalid_cli_usage(message: String) -> Box<dyn Error> {
    std::io::Error::other(format!("{message}\n\n{}", help_text())).into()
}

fn print_help() {
    println!("{}", help_text());
}

fn help_text() -> String {
    format!(
        "Tracey {}\n\n\
Usage:\n\
  tracey\n\
  tracey --ebpf disabled|auto|required\n\
  tracey status [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-ban status [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-ban ban --jail NAME --ip IP [--reason TEXT] [--source TEXT] [--ban-time-ms MS] [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-ban unban --jail NAME --ip IP [--reason TEXT] [--source TEXT] [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-ban refresh-backend [--jail NAME] [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-ban filters [--json]\n\
  tracey tracey-ban actions [--json]\n\
  tracey tracey-guard status [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-guard enable [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-guard disable [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-guard deep-dive on|off [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-guard tmr on|off [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-guard set-overhead --pct FLOAT [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-guard set-parallelism --count N [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey tracey-guard force-scan [--addr ADDR] [--token TOKEN] [--timeout-ms MS] [--json]\n\
  tracey sign-update ...\n\
  tracey --tui\n\
  tracey --supervisor\n\n\
Runtime Overrides:\n\
  --ebpf MODE      Override embedded network eBPF mode. Default is `auto`; `auto` attempts kernel capture and degrades cleanly, while `required` aborts startup when eBPF is unavailable.\n\n\
Environment:\n\
  TRACEY_CONFIG       Path to Tracey JSON config\n\
  TRACEY_STATUS_ADDR  Override status API address for CLI commands\n\
  TRACEY_STATUS_TOKEN Bearer token for protected status/control endpoints\n\
  TRACEY_AUTH_BEARER  Alternate bearer token env name\n",
        crate::package_version()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_status_base_rewrites_unspecified_hosts() {
        let url = normalize_status_base("0.0.0.0:48000").expect("url");
        assert_eq!(url.as_str(), "http://127.0.0.1:48000/");

        let url = normalize_status_base("http://[::]:48000/status").expect("url");
        assert_eq!(url.as_str(), "http://[::1]:48000/");
    }

    #[test]
    fn normalize_status_base_keeps_proxy_prefix_and_strips_endpoint() {
        let url = normalize_status_base("https://tracey.example.com/proxy/status").expect("url");
        assert_eq!(url.as_str(), "https://tracey.example.com/proxy");
    }

    #[test]
    fn parse_tracey_ban_ban_command_collects_fields() {
        let args = vec![
            "tracey".to_string(),
            "tracey-ban".to_string(),
            "ban".to_string(),
            "--jail".to_string(),
            "sshd-auth".to_string(),
            "--ip".to_string(),
            "203.0.113.50".to_string(),
            "--reason".to_string(),
            "manual".to_string(),
            "--json".to_string(),
        ];

        let parsed = parse_cli_command(&args).expect("parsed").expect("command");
        match parsed {
            ParsedCliCommand::TraceyBanBan {
                http,
                jail,
                ip,
                reason,
                ..
            } => {
                assert!(http.json);
                assert_eq!(jail, "sshd-auth");
                assert_eq!(ip, "203.0.113.50");
                assert_eq!(reason.as_deref(), Some("manual"));
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_status_command_collects_http_options() {
        let args = vec![
            "tracey".to_string(),
            "status".to_string(),
            "--addr".to_string(),
            "127.0.0.1:48000".to_string(),
            "--token".to_string(),
            "abc".to_string(),
            "--timeout-ms".to_string(),
            "2500".to_string(),
            "--json".to_string(),
        ];

        let parsed = parse_cli_command(&args).expect("parsed").expect("command");
        match parsed {
            ParsedCliCommand::Status(http) => {
                assert_eq!(http.addr.as_deref(), Some("127.0.0.1:48000"));
                assert_eq!(http.token.as_deref(), Some("abc"));
                assert_eq!(http.timeout_ms, Some(2500));
                assert!(http.json);
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_tracey_guard_toggle_command_collects_state_and_http_options() {
        let args = vec![
            "tracey".to_string(),
            "tracey_guard".to_string(),
            "deep_dive".to_string(),
            "on".to_string(),
            "--timeout-ms".to_string(),
            "1800".to_string(),
            "--json".to_string(),
        ];

        let parsed = parse_cli_command(&args).expect("parsed").expect("command");
        match parsed {
            ParsedCliCommand::TraceyGuardDeepDive { http, enabled } => {
                assert!(enabled);
                assert_eq!(http.timeout_ms, Some(1800));
                assert!(http.json);
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_tracey_guard_set_parallelism_collects_count() {
        let args = vec![
            "tracey".to_string(),
            "tracey-guard".to_string(),
            "set-parallelism".to_string(),
            "--count".to_string(),
            "12".to_string(),
            "--addr".to_string(),
            "127.0.0.1:48000".to_string(),
        ];

        let parsed = parse_cli_command(&args).expect("parsed").expect("command");
        match parsed {
            ParsedCliCommand::TraceyGuardSetParallelism { http, count } => {
                assert_eq!(count, 12);
                assert_eq!(http.addr.as_deref(), Some("127.0.0.1:48000"));
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_runtime_start_options_collects_ebpf_mode() {
        let args = vec![
            "tracey".to_string(),
            "--ebpf".to_string(),
            "required".to_string(),
        ];
        let parsed = parse_runtime_start_options(&args).expect("runtime options");
        assert_eq!(parsed.ebpf_mode.as_deref(), Some("required"));
    }

    #[test]
    fn parse_runtime_start_options_supports_equals_syntax() {
        let args = vec!["tracey".to_string(), "--ebpf=auto".to_string()];
        let parsed = parse_runtime_start_options(&args).expect("runtime options");
        assert_eq!(parsed.ebpf_mode.as_deref(), Some("auto"));
    }

    #[test]
    fn parse_runtime_start_options_rejects_invalid_ebpf_mode() {
        let args = vec![
            "tracey".to_string(),
            "--ebpf".to_string(),
            "aggressive".to_string(),
        ];
        let err = parse_runtime_start_options(&args).expect_err("invalid mode");
        assert!(err.to_string().contains("invalid value for --ebpf"));
    }
}
