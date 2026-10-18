//! Bounded connectivity checks for fixed endpoints. This module never starts or
//! stops a strategy and never executes the upstream test script.

use serde::{Deserialize, Serialize};
use std::io;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

const CURL_MAX_TIME: Duration = Duration::from_secs(4);
const PROCESS_DEADLINE: Duration = Duration::from_secs(6);
const POLL_INTERVAL: Duration = Duration::from_millis(40);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum EndpointCategory {
    #[serde(rename = "youtube")]
    YouTube,
    Discord,
    Google,
    Cloudflare,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProbeVariant {
    Http11,
    Tls12,
    Tls13,
}

impl ProbeVariant {
    pub(crate) const ALL: [Self; 3] = [Self::Http11, Self::Tls12, Self::Tls13];

    fn args(self) -> &'static [&'static str] {
        match self {
            Self::Http11 => &["--http1.1"],
            Self::Tls12 => &["--tlsv1.2", "--tls-max", "1.2"],
            Self::Tls13 => &["--tlsv1.3", "--tls-max", "1.3"],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProbeStatus {
    Passed,
    Failed,
    Unsupported,
    Skipped,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbeEndpoint {
    pub key: &'static str,
    pub url: &'static str,
    pub category: EndpointCategory,
}

pub(crate) const ENDPOINTS: [ProbeEndpoint; 11] = [
    ProbeEndpoint {
        key: "DiscordMain",
        url: "https://discord.com",
        category: EndpointCategory::Discord,
    },
    ProbeEndpoint {
        key: "DiscordGateway",
        url: "https://gateway.discord.gg",
        category: EndpointCategory::Discord,
    },
    ProbeEndpoint {
        key: "DiscordCDN",
        url: "https://cdn.discordapp.com",
        category: EndpointCategory::Discord,
    },
    ProbeEndpoint {
        key: "DiscordUpdates",
        url: "https://updates.discord.com",
        category: EndpointCategory::Discord,
    },
    ProbeEndpoint {
        key: "YouTubeWeb",
        url: "https://www.youtube.com",
        category: EndpointCategory::YouTube,
    },
    ProbeEndpoint {
        key: "YouTubeShort",
        url: "https://youtu.be",
        category: EndpointCategory::YouTube,
    },
    ProbeEndpoint {
        key: "YouTubeImage",
        url: "https://i.ytimg.com",
        category: EndpointCategory::YouTube,
    },
    ProbeEndpoint {
        key: "GoogleMain",
        url: "https://www.google.com",
        category: EndpointCategory::Google,
    },
    ProbeEndpoint {
        key: "GoogleGstatic",
        url: "https://www.gstatic.com",
        category: EndpointCategory::Google,
    },
    ProbeEndpoint {
        key: "CloudflareWeb",
        url: "https://www.cloudflare.com",
        category: EndpointCategory::Cloudflare,
    },
    ProbeEndpoint {
        key: "CloudflareCDN",
        url: "https://cdnjs.cloudflare.com",
        category: EndpointCategory::Cloudflare,
    },
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProbeResult {
    pub endpoint_key: String,
    pub category: EndpointCategory,
    pub url: String,
    pub variant: ProbeVariant,
    pub status: ProbeStatus,
    #[serde(rename = "httpStatus")]
    pub http_code: Option<u16>,
    #[serde(rename = "durationMs")]
    pub elapsed_ms: Option<u64>,
    #[serde(rename = "error")]
    pub detail: Option<String>,
}

impl ProbeResult {
    fn new(endpoint: &'static ProbeEndpoint, variant: ProbeVariant) -> Self {
        Self {
            endpoint_key: endpoint.key.to_owned(),
            category: endpoint.category,
            url: endpoint.url.to_owned(),
            variant,
            status: ProbeStatus::Failed,
            http_code: None,
            elapsed_ms: None,
            detail: None,
        }
    }
}

pub(crate) fn skipped(endpoint: &'static ProbeEndpoint, variant: ProbeVariant) -> ProbeResult {
    let mut result = ProbeResult::new(endpoint, variant);
    result.status = ProbeStatus::Skipped;
    result
}

/// Checks one fixed endpoint. Cancellation terminates only the curl child
/// launched by this call. A response of any HTTP status is a passing probe.
pub(crate) fn probe_one(
    endpoint: &'static ProbeEndpoint,
    variant: ProbeVariant,
    is_cancelled: impl Fn() -> bool,
) -> ProbeResult {
    if is_cancelled() {
        return skipped(endpoint, variant);
    }

    let mut result = ProbeResult::new(endpoint, variant);
    let curl = match system_curl_path() {
        Ok(path) => path,
        Err(detail) => {
            result.status = ProbeStatus::Unsupported;
            result.detail = Some(detail);
            return result;
        }
    };
    let started = Instant::now();
    let child = Command::new(curl)
        .arg("--disable")
        .arg("--head")
        .arg("--silent")
        .arg("--show-error")
        .arg("--max-time")
        .arg(CURL_MAX_TIME.as_secs().to_string())
        .arg("--connect-timeout")
        .arg("2")
        .arg("--output")
        .arg("NUL")
        .arg("--write-out")
        .arg("%{http_code}")
        .args(variant.args())
        .arg(endpoint.url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            result.status = if error.kind() == io::ErrorKind::NotFound {
                ProbeStatus::Unsupported
            } else {
                ProbeStatus::Failed
            };
            result.detail = Some(format!("Не удалось запустить системный curl: {error}"));
            return result;
        }
    };

    let exit = loop {
        if is_cancelled() {
            stop_child(&mut child);
            result.status = ProbeStatus::Skipped;
            result.elapsed_ms = Some(elapsed_ms(started));
            result.detail = Some("Проверка отменена.".into());
            return result;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < PROCESS_DEADLINE => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                stop_child(&mut child);
                result.elapsed_ms = Some(elapsed_ms(started));
                result.detail = Some("Превышено время ожидания проверки.".into());
                return result;
            }
            Err(error) => {
                stop_child(&mut child);
                result.elapsed_ms = Some(elapsed_ms(started));
                result.detail = Some(format!("Не удалось дождаться проверки: {error}"));
                return result;
            }
        }
    };

    // curl writes only the HTTP code to stdout. stderr is bounded when shown
    // to the UI; raw output never becomes a command or a URL.
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            result.elapsed_ms = Some(elapsed_ms(started));
            result.detail = Some(format!("Не удалось прочитать результат: {error}"));
            return result;
        }
    };
    result.elapsed_ms = Some(elapsed_ms(started));
    result.http_code = parse_http_code(&output.stdout);
    result.status = classify(exit, result.http_code);
    if result.status != ProbeStatus::Passed {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr
            .split_whitespace()
            .take(24)
            .collect::<Vec<_>>()
            .join(" ");
        result.detail = Some(if detail.is_empty() {
            format!("curl завершился с кодом {}.", exit.code().unwrap_or(-1))
        } else {
            detail.chars().take(180).collect()
        });
    }
    result
}

fn parse_http_code(output: &[u8]) -> Option<u16> {
    let value = std::str::from_utf8(output).ok()?.trim();
    if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let code = value.parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}

fn classify(exit: ExitStatus, code: Option<u16>) -> ProbeStatus {
    if code.is_some() {
        ProbeStatus::Passed
    } else if matches!(exit.code(), Some(4 | 48)) {
        ProbeStatus::Unsupported
    } else {
        ProbeStatus::Failed
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn system_curl_path() -> Result<PathBuf, String> {
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("Не удалось найти системный каталог Windows.".into());
    }
    use std::os::windows::ffi::OsStringExt;
    let mut path = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]));
    path.push("curl.exe");
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_targets_match_selected_service_groups() {
        assert_eq!(ENDPOINTS.len(), 11);
        for category in [
            EndpointCategory::Discord,
            EndpointCategory::YouTube,
            EndpointCategory::Google,
            EndpointCategory::Cloudflare,
        ] {
            assert_eq!(
                ENDPOINTS
                    .iter()
                    .filter(|item| item.category == category)
                    .count(),
                match category {
                    EndpointCategory::Discord => 4,
                    EndpointCategory::YouTube => 3,
                    EndpointCategory::Google | EndpointCategory::Cloudflare => 2,
                }
            );
        }
        assert!(ENDPOINTS
            .iter()
            .all(|item| item.url.starts_with("https://")));
    }

    #[test]
    fn exact_variants_and_http_response_rule() {
        assert_eq!(ProbeVariant::Http11.args(), ["--http1.1"]);
        assert_eq!(
            ProbeVariant::Tls12.args(),
            ["--tlsv1.2", "--tls-max", "1.2"]
        );
        assert_eq!(
            ProbeVariant::Tls13.args(),
            ["--tlsv1.3", "--tls-max", "1.3"]
        );
        assert_eq!(parse_http_code(b"404"), Some(404));
        assert_eq!(parse_http_code(b"000"), None);
        assert_eq!(parse_http_code(b"200\n"), Some(200));
        assert_eq!(parse_http_code(b"200 garbage"), None);
    }

    #[test]
    fn cancellation_before_launch_is_skipped() {
        let result = probe_one(&ENDPOINTS[0], ProbeVariant::Http11, || true);
        assert_eq!(result.status, ProbeStatus::Skipped);
        assert!(result.elapsed_ms.is_none());
    }

    #[test]
    fn result_round_trips_through_helper_ipc() {
        let result = skipped(&ENDPOINTS[4], ProbeVariant::Tls13);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["category"], "youtube");
        assert_eq!(json["variant"], "tls13");
        assert_eq!(json["status"], "skipped");
        assert!(json.get("httpStatus").is_some());
        assert!(json.get("durationMs").is_some());
        assert!(json.get("error").is_some());
        let restored: ProbeResult = serde_json::from_value(json).unwrap();
        assert_eq!(restored.endpoint_key, result.endpoint_key);
    }
}
