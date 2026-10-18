//! Safe downloader for the official Flowseal GitHub release.
//!
//! Network access is deliberately limited to the fixed GitHub API endpoint and
//! its official release asset hosts. No process or shell is involved.

use crate::error::AppError;
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};

const API_HOST: &str = "api.github.com";
const API_PATH: &str = "/repos/Flowseal/zapret-discord-youtube/releases/latest";
const RELEASE_HOST: &str = "github.com";
const RELEASE_CDN_HOSTS: &[&str] = &[
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const READ_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DownloadedRelease {
    pub tag: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
struct ReleaseMetadata {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedRelease {
    tag: String,
    url: String,
    size: u64,
    sha256: String,
}

/// Fetches and validates the latest official release, then atomically places
/// the verified archive at `destination`. `trusted_root` must already exist.
/// Progress reports `(downloaded bytes, total bytes)` during the archive read.
pub(crate) fn download_latest_release<F>(
    destination: &Path,
    trusted_root: &Path,
    mut progress: F,
) -> Result<DownloadedRelease, AppError>
where
    F: FnMut(u64, u64),
{
    let destination = validate_destination(destination, trusted_root)?;
    let release = fetch_release_metadata()?;
    let (temp_path, mut temp_file) = create_temp_file(&destination)?;
    let download_result = download_and_verify(&release, &mut temp_file, &mut progress);
    drop(temp_file);
    let outcome = download_result
        .and_then(|()| std::fs::rename(&temp_path, &destination).map_err(|_| io_error()));
    if outcome.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    outcome?;

    Ok(DownloadedRelease {
        tag: release.tag,
        path: destination,
        bytes: release.size,
        sha256: release.sha256,
    })
}

fn validate_release_metadata(bytes: &[u8]) -> Result<ValidatedRelease, AppError> {
    let metadata: ReleaseMetadata = serde_json::from_slice(bytes).map_err(|_| metadata_error())?;
    if metadata.draft || metadata.prerelease || !valid_tag(&metadata.tag_name) {
        return Err(metadata_error());
    }

    let expected_name = format!("zapret-discord-youtube-{}.zip", metadata.tag_name);
    let mut matching = metadata
        .assets
        .iter()
        .filter(|asset| asset.name == expected_name);
    let asset = matching.next().ok_or_else(metadata_error)?;
    if matching.next().is_some() || asset.size == 0 || asset.size > MAX_ARCHIVE_BYTES {
        return Err(metadata_error());
    }

    let expected_url = format!(
        "https://github.com/Flowseal/zapret-discord-youtube/releases/download/{}/{}",
        metadata.tag_name, expected_name
    );
    if asset.browser_download_url != expected_url {
        return Err(metadata_error());
    }

    let sha256 = parse_sha256_digest(asset.digest.as_deref().ok_or_else(metadata_error)?)?;
    Ok(ValidatedRelease {
        tag: metadata.tag_name,
        url: expected_url,
        size: asset.size,
        sha256,
    })
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && !tag.starts_with('.')
        && !tag.contains("..")
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn parse_sha256_digest(digest: &str) -> Result<String, AppError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(metadata_error());
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(metadata_error());
    }
    Ok(hex.to_ascii_lowercase())
}

fn validate_destination(destination: &Path, trusted_root: &Path) -> Result<PathBuf, AppError> {
    if !destination.is_absolute() || !trusted_root.is_absolute() {
        return Err(destination_error());
    }
    if destination
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(destination_error());
    }
    let filename = destination.file_name().ok_or_else(destination_error)?;
    let Some(filename_text) = filename.to_str() else {
        return Err(destination_error());
    };
    if filename_text.is_empty()
        || filename_text == "."
        || filename_text == ".."
        || !filename_text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(destination_error());
    }
    let root = trusted_root
        .canonicalize()
        .map_err(|_| destination_error())?;
    let parent = destination.parent().ok_or_else(destination_error)?;
    let canonical_parent = parent.canonicalize().map_err(|_| destination_error())?;
    if !canonical_parent.starts_with(&root) {
        return Err(destination_error());
    }
    let canonical_destination = canonical_parent.join(filename);
    if canonical_destination.exists() {
        return Err(destination_error());
    }
    Ok(canonical_destination)
}

fn create_temp_file(destination: &Path) -> Result<(PathBuf, std::fs::File), AppError> {
    static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = destination.parent().ok_or_else(destination_error)?;
    let name = destination
        .file_name()
        .ok_or_else(destination_error)?
        .to_string_lossy();
    for _ in 0..8 {
        let serial = NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{name}.zapret-{}-{serial}.part",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(io_error()),
        }
    }
    Err(io_error())
}

#[cfg(windows)]
fn fetch_release_metadata() -> Result<ValidatedRelease, AppError> {
    let bytes = winhttp::get_bytes(&format!("https://{API_HOST}{API_PATH}"), MAX_METADATA_BYTES)?;
    validate_release_metadata(&bytes)
}

#[cfg(not(windows))]
fn fetch_release_metadata() -> Result<ValidatedRelease, AppError> {
    Err(network_error())
}

#[cfg(windows)]
fn download_and_verify<F>(
    release: &ValidatedRelease,
    output: &mut std::fs::File,
    progress: &mut F,
) -> Result<(), AppError>
where
    F: FnMut(u64, u64),
{
    winhttp::download_file(release, output, progress)
}

#[cfg(not(windows))]
fn download_and_verify<F>(
    _release: &ValidatedRelease,
    _output: &mut std::fs::File,
    _progress: &mut F,
) -> Result<(), AppError>
where
    F: FnMut(u64, u64),
{
    Err(network_error())
}

fn metadata_error() -> AppError {
    AppError::new(
        "upstream_release_invalid",
        "Не удалось проверить официальный релиз zapret.",
        "Повторите попытку позже. Текущая установка не была изменена.",
    )
}

fn destination_error() -> AppError {
    AppError::new(
        "update_destination_invalid",
        "Папка для временной загрузки недоступна или находится вне разрешённой области.",
        "Повторите обновление через приложение. Текущая установка не была изменена.",
    )
}

fn network_error() -> AppError {
    AppError::new(
        "upstream_download_failed",
        "Не удалось загрузить официальный релиз zapret.",
        "Проверьте подключение к интернету и повторите попытку. Текущая установка не была изменена.",
    )
}

fn io_error() -> AppError {
    AppError::new(
        "upstream_archive_write_failed",
        "Не удалось сохранить загруженный архив zapret.",
        "Проверьте свободное место и права доступа к папке обновления.",
    )
}

#[cfg(windows)]
mod winhttp {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::ffi::c_void;
    use std::fs::File;
    use std::io::Write;
    use std::ptr::{null, null_mut};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Networking::WinHttp::*;

    const REQUEST_TIMEOUT_MS: i32 = 15_000;
    const METADATA_TIMEOUT_MS: i32 = 30_000;
    const METADATA_DEADLINE: Duration = Duration::from_secs(90);
    const ARCHIVE_DEADLINE: Duration = Duration::from_secs(600);

    struct InternetHandle(*mut c_void);

    struct ResponseHandles {
        // Declare in child-to-parent order so Rust closes request, connection,
        // then session at scope exit.
        request: InternetHandle,
        _connection: InternetHandle,
        _session: InternetHandle,
    }

    impl InternetHandle {
        fn new(raw: *mut c_void) -> Result<Self, AppError> {
            if raw.is_null() {
                Err(network_error())
            } else {
                Ok(Self(raw))
            }
        }
    }

    impl Drop for InternetHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    WinHttpCloseHandle(self.0);
                }
            }
        }
    }

    struct ParsedUrl<'a> {
        host: &'a str,
        path: &'a str,
    }

    fn parse_url<'a>(url: &'a str, allowed_hosts: &[&str]) -> Result<ParsedUrl<'a>, AppError> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| network_error())?;
        let split = rest.find('/').ok_or_else(|| network_error())?;
        let host = &rest[..split];
        let path = &rest[split..];
        if !allowed_hosts
            .iter()
            .any(|allowed| host.eq_ignore_ascii_case(allowed))
            || host.contains('@')
            || host.contains(':')
            || url
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'#')
        {
            return Err(network_error());
        }
        Ok(ParsedUrl { host, path })
    }

    fn get_session() -> Result<InternetHandle, AppError> {
        let agent: Vec<u16> = "ZapretGui/0.1 (Windows; official Flowseal release updater)\0"
            .encode_utf16()
            .collect();
        let session = unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                null(),
                null(),
                0,
            )
        };
        let session = InternetHandle::new(session)?;
        if unsafe {
            WinHttpSetTimeouts(
                session.0,
                REQUEST_TIMEOUT_MS,
                REQUEST_TIMEOUT_MS,
                REQUEST_TIMEOUT_MS,
                METADATA_TIMEOUT_MS,
            )
        } == 0
        {
            return Err(network_error());
        }
        Ok(session)
    }

    fn request(
        url: &str,
        allowed_current_hosts: &[&str],
        redirect_hosts: &[&str],
        accept: &str,
    ) -> Result<(ResponseHandles, u32), AppError> {
        let session = get_session()?;
        let mut current_url = url.to_owned();
        for redirect_count in 0..=MAX_REDIRECTS {
            let parsed = parse_url(&current_url, allowed_current_hosts)?;
            let host_wide = to_wide(parsed.host);
            let connection = InternetHandle::new(unsafe {
                WinHttpConnect(session.0, host_wide.as_ptr(), 443, 0)
            })?;
            let get = to_wide("GET");
            let path = to_wide(parsed.path);
            let version = to_wide("HTTP/1.1");
            let request_handle = InternetHandle::new(unsafe {
                WinHttpOpenRequest(
                    connection.0,
                    get.as_ptr(),
                    path.as_ptr(),
                    version.as_ptr(),
                    null(),
                    null(),
                    WINHTTP_FLAG_SECURE,
                )
            })?;

            let no_redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            if unsafe {
                WinHttpSetOption(
                    request_handle.0,
                    WINHTTP_OPTION_REDIRECT_POLICY,
                    (&no_redirect as *const u32).cast(),
                    std::mem::size_of_val(&no_redirect) as u32,
                )
            } == 0
            {
                return Err(network_error());
            }
            let headers = to_wide(&format!(
                "Accept: {accept}\r\nUser-Agent: ZapretGui/0.1\r\n"
            ));
            if unsafe {
                WinHttpAddRequestHeaders(
                    request_handle.0,
                    headers.as_ptr(),
                    u32::MAX,
                    WINHTTP_ADDREQ_FLAG_ADD,
                )
            } == 0
                || unsafe { WinHttpSendRequest(request_handle.0, null(), 0, null(), 0, 0, 0) } == 0
                || unsafe { WinHttpReceiveResponse(request_handle.0, null_mut()) } == 0
            {
                return Err(network_error());
            }

            let status = query_number(request_handle.0, WINHTTP_QUERY_STATUS_CODE)?;
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if redirect_count == MAX_REDIRECTS {
                    return Err(network_error());
                }
                let location = query_string(request_handle.0, WINHTTP_QUERY_LOCATION)?;
                let next = validate_redirect(
                    &current_url,
                    &location,
                    allowed_current_hosts,
                    redirect_hosts,
                )?;
                current_url = next;
                continue;
            }
            if status != 200 {
                return Err(network_error());
            }
            return Ok((
                ResponseHandles {
                    request: request_handle,
                    _connection: connection,
                    _session: session,
                },
                status,
            ));
        }
        Err(network_error())
    }

    fn read_response(
        handle: *mut c_void,
        max_bytes: u64,
        started: Instant,
        deadline: Duration,
        mut sink: impl FnMut(&[u8]) -> Result<(), AppError>,
    ) -> Result<u64, AppError> {
        let content_length = query_number(handle, WINHTTP_QUERY_CONTENT_LENGTH)
            .ok()
            .map(u64::from);
        if content_length.is_some_and(|length| length > max_bytes) {
            return Err(metadata_error());
        }
        let mut total = 0u64;
        let mut buffer = [0u8; READ_CHUNK_BYTES];
        loop {
            if started.elapsed() >= deadline {
                return Err(network_error());
            }
            let mut read = 0u32;
            let ok = unsafe {
                WinHttpReadData(
                    handle,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut read,
                )
            };
            if ok == 0 {
                return Err(network_error());
            }
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| metadata_error())?;
            if total > max_bytes {
                return Err(metadata_error());
            }
            sink(&buffer[..read as usize])?;
        }
        if content_length.is_some_and(|length| length != total) {
            return Err(network_error());
        }
        Ok(total)
    }

    pub(super) fn get_bytes(url: &str, max_bytes: u64) -> Result<Vec<u8>, AppError> {
        let started = Instant::now();
        let (response, _) = request(url, &[API_HOST], &[], "application/vnd.github+json")?;
        let mut bytes = Vec::new();
        read_response(
            response.request.0,
            max_bytes,
            started,
            METADATA_DEADLINE,
            |chunk| {
                bytes.extend_from_slice(chunk);
                Ok(())
            },
        )?;
        Ok(bytes)
    }

    pub(super) fn download_file<F>(
        release: &ValidatedRelease,
        output: &mut File,
        progress: &mut F,
    ) -> Result<(), AppError>
    where
        F: FnMut(u64, u64),
    {
        let started = Instant::now();
        let allowed_hosts = [RELEASE_HOST, RELEASE_CDN_HOSTS[0], RELEASE_CDN_HOSTS[1]];
        let (response, _) = request(
            &release.url,
            &allowed_hosts,
            RELEASE_CDN_HOSTS,
            "application/octet-stream",
        )?;
        progress(0, release.size);
        let mut hasher = Sha256::new();
        let mut downloaded = 0u64;
        let total = read_response(
            response.request.0,
            MAX_ARCHIVE_BYTES,
            started,
            ARCHIVE_DEADLINE,
            |chunk| {
                downloaded = downloaded
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(|| network_error())?;
                output.write_all(chunk).map_err(|_| io_error())?;
                hasher.update(chunk);
                progress(downloaded, release.size);
                Ok(())
            },
        )?;
        if total != release.size {
            return Err(network_error());
        }
        let actual = hex_digest(&hasher.finalize());
        if actual != release.sha256 {
            return Err(AppError::new(
                "upstream_checksum_mismatch",
                "Контрольная сумма архива zapret не совпала с данными GitHub.",
                "Архив отклонён, текущая установка не была изменена. Повторите загрузку позже.",
            ));
        }
        output.flush().map_err(|_| io_error())?;
        output.sync_all().map_err(|_| io_error())?;
        Ok(())
    }

    fn query_number(handle: *mut c_void, query: u32) -> Result<u32, AppError> {
        let mut value = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let ok = unsafe {
            WinHttpQueryHeaders(
                handle,
                query | WINHTTP_QUERY_FLAG_NUMBER,
                null(),
                (&mut value as *mut u32).cast(),
                &mut size,
                null_mut(),
            )
        };
        if ok == 0 {
            Err(network_error())
        } else {
            Ok(value)
        }
    }

    fn query_string(handle: *mut c_void, query: u32) -> Result<String, AppError> {
        let mut size = 0u32;
        unsafe {
            WinHttpQueryHeaders(handle, query, null(), null_mut(), &mut size, null_mut());
        }
        if size < 2 || size > 64 * 1024 {
            return Err(network_error());
        }
        let mut value = vec![0u16; (size as usize + 1) / 2];
        let ok = unsafe {
            WinHttpQueryHeaders(
                handle,
                query,
                null(),
                value.as_mut_ptr().cast(),
                &mut size,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(network_error());
        }
        let end = value
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(value.len());
        String::from_utf16(&value[..end]).map_err(|_| network_error())
    }

    fn validate_redirect(
        current: &str,
        location: &str,
        allowed_current_hosts: &[&str],
        redirect_hosts: &[&str],
    ) -> Result<String, AppError> {
        let _ = parse_url(current, allowed_current_hosts)?;
        let target = if location.starts_with("https://") {
            location.to_owned()
        } else if location.starts_with('/') {
            let current_url = parse_url(current, allowed_current_hosts)?;
            format!("https://{}{}", current_url.host, location)
        } else {
            return Err(network_error());
        };
        let next = parse_url(&target, redirect_hosts)?;
        if !redirect_hosts
            .iter()
            .any(|host| next.host.eq_ignore_ascii_case(host))
        {
            return Err(network_error());
        }
        Ok(target)
    }

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn hex_digest(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(tag: &str, url: &str, digest: &str) -> Vec<u8> {
        serde_json::json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": false,
            "assets": [{
                "name": format!("zapret-discord-youtube-{tag}.zip"),
                "browser_download_url": url,
                "size": 1024,
                "digest": digest
            }]
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn accepts_expected_release_metadata() {
        let tag = "1.10.3";
        let url = format!(
            "https://github.com/Flowseal/zapret-discord-youtube/releases/download/{tag}/zapret-discord-youtube-{tag}.zip"
        );
        let release =
            validate_release_metadata(&metadata(tag, &url, &format!("sha256:{}", "a".repeat(64))))
                .expect("valid metadata");
        assert_eq!(release.tag, tag);
        assert_eq!(release.size, 1024);
        assert_eq!(release.sha256, "a".repeat(64));
    }

    #[test]
    fn rejects_unsafe_or_invalid_tags() {
        for tag in ["", "../x", "bad tag", "v1/2", ".hidden", "a..b", "a?b"] {
            assert!(!valid_tag(tag), "unexpectedly accepted {tag:?}");
        }
        assert!(valid_tag("1.10.3"));
        assert!(valid_tag("v1_2-rc"));
    }

    #[test]
    fn rejects_draft_prerelease_wrong_url_missing_digest_and_large_asset() {
        let tag = "1.10.3";
        let expected = format!(
            "https://github.com/Flowseal/zapret-discord-youtube/releases/download/{tag}/zapret-discord-youtube-{tag}.zip"
        );
        let digest = format!("sha256:{}", "b".repeat(64));
        assert!(validate_release_metadata(&metadata("../bad", &expected, &digest)).is_err());
        assert!(validate_release_metadata(&metadata(
            tag,
            "https://evil.example/file.zip",
            &digest
        ))
        .is_err());
        assert!(parse_sha256_digest("sha1:abcd").is_err());
        assert!(parse_sha256_digest("sha256:abcd").is_err());
        assert!(parse_sha256_digest(&format!("sha256:{}", "g".repeat(64))).is_err());

        let mut value: serde_json::Value =
            serde_json::from_slice(&metadata(tag, &expected, &digest)).unwrap();
        value["draft"] = serde_json::json!(true);
        assert!(validate_release_metadata(&value.to_string().into_bytes()).is_err());
        value["draft"] = serde_json::json!(false);
        value["prerelease"] = serde_json::json!(true);
        assert!(validate_release_metadata(&value.to_string().into_bytes()).is_err());
        value["prerelease"] = serde_json::json!(false);
        value["assets"][0]["size"] = serde_json::json!(MAX_ARCHIVE_BYTES + 1);
        assert!(validate_release_metadata(&value.to_string().into_bytes()).is_err());
    }
}
