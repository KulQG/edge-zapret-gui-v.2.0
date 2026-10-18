//! Read-only inspection of the managed engine and relevant Windows components.
//!
//! This module deliberately has no service, process, or filesystem mutation API.

use serde::Serialize;
use std::ffi::OsString;
use std::fs;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NO_MORE_FILES, ERROR_SERVICE_DOES_NOT_EXIST,
    INVALID_HANDLE_VALUE, SYSTEMTIME,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx,
    QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CONTINUE_PENDING,
    SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
    SERVICE_STOP_PENDING,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTime;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsSnapshot {
    pub checked_at: String,
    pub paths: DiagnosticPaths,
    pub engine: EngineDiagnostic,
    pub service: ServiceDiagnostic,
    pub win_divert: WinDivertDiagnostic,
    pub processes: Vec<ProcessDiagnostic>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticPaths {
    pub config_dir: String,
    pub data_dir: String,
    pub engine_dir: String,
    pub log_dir: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineDiagnostic {
    pub installed: bool,
    pub ready: bool,
    pub issue: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDiagnostic {
    pub installed: bool,
    pub state: String,
    pub process_id: Option<u32>,
    pub strategy: Option<String>,
    pub executable_path: Option<String>,
    pub managed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WinDivertDiagnostic {
    pub installed: bool,
    pub managed: bool,
    pub state: String,
    pub name: Option<String>,
    pub driver_file_present: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessDiagnostic {
    pub pid: u32,
    pub executable_path: Option<String>,
    pub managed: bool,
    pub error: Option<String>,
}

#[derive(Clone, Copy)]
enum ServiceKind {
    Zapret,
    WinDivert,
}

struct RawService {
    installed: bool,
    state: String,
    process_id: Option<u32>,
    executable_path: Option<String>,
    error: Option<String>,
}

struct ScHandle(windows_sys::Win32::System::Services::SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

struct ProcessHandle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub fn collect() -> Result<DiagnosticsSnapshot, String> {
    let local_app_data = known_folder(&FOLDERID_LocalAppData)
        .map_err(|e| format!("Не удалось определить папку LocalAppData: {e}"))?;
    let program_data = known_folder(&FOLDERID_ProgramData)
        .map_err(|e| format!("Не удалось определить папку ProgramData: {e}"))?;

    let data_dir = program_data.join("ZapretGui");
    let engine_dir = data_dir.join("engine").join("current");
    let config_dir = local_app_data.join("ZapretGui").join("config");
    let log_dir = local_app_data.join("ZapretGui").join("logs");
    let managed_engine = fs::canonicalize(&engine_dir).ok();

    let engine = inspect_engine(&engine_dir);
    let raw_zapret = inspect_service("zapret", ServiceKind::Zapret);
    let zapret_pid = raw_zapret.process_id;
    let service = ServiceDiagnostic {
        installed: raw_zapret.installed,
        state: raw_zapret.state,
        process_id: raw_zapret.process_id,
        strategy: if raw_zapret.installed {
            read_service_strategy()
        } else {
            None
        },
        managed: raw_zapret
            .executable_path
            .as_ref()
            .map(|p| is_managed_winws(Path::new(p), managed_engine.as_deref()))
            .unwrap_or(false),
        executable_path: raw_zapret.executable_path,
        error: raw_zapret.error,
    };

    let win_divert = inspect_windivert(&engine_dir);
    let (processes, process_error) = inspect_winws_processes(managed_engine.as_deref());
    let mut warnings = Vec::new();
    if let Some(error) = process_error {
        warnings.push(error);
    }
    if service.installed && !service.managed {
        warnings.push("Служба zapret обнаружена, но её путь не подтверждён как управляемый этим приложением. Не изменяйте её без проверки владельца установки.".to_owned());
    }
    if processes.iter().any(|process| !process.managed) {
        warnings.push("Найден winws.exe вне папки приложения или с недоступным путём. Его нельзя считать управляемым процессом.".to_owned());
    }
    if service.state == "running"
        && processes
            .iter()
            .any(|process| process.managed && Some(process.pid) != zapret_pid)
    {
        warnings.push("Служба zapret и отдельный winws.exe могут одновременно влиять на соединение. Проверьте активный режим перед запуском стратегии.".to_owned());
    }

    Ok(DiagnosticsSnapshot {
        checked_at: utc_now(),
        paths: DiagnosticPaths {
            config_dir: display_path(&config_dir),
            data_dir: display_path(&data_dir),
            engine_dir: display_path(&engine_dir),
            log_dir: display_path(&log_dir),
        },
        engine,
        service,
        win_divert,
        processes,
        warnings,
    })
}

fn known_folder(folder: &GUID) -> Result<PathBuf, String> {
    let mut raw = null_mut();
    let status = unsafe { SHGetKnownFolderPath(folder, 0, null_mut(), &mut raw) };
    if status < 0 {
        return Err(format!("ошибка Windows 0x{:08X}", status as u32));
    }
    if raw.is_null() {
        return Err("Windows вернула пустой путь".to_owned());
    }
    let path = unsafe {
        let mut len = 0;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let value = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(raw, len)));
        CoTaskMemFree(raw.cast());
        value
    };
    Ok(path)
}

pub(crate) fn local_app_data() -> Result<PathBuf, String> {
    known_folder(&FOLDERID_LocalAppData)
}

pub(crate) fn engine_dir() -> Result<PathBuf, String> {
    known_folder(&FOLDERID_ProgramData)
        .map(|path| path.join("ZapretGui").join("engine").join("current"))
}

pub(crate) fn program_files_dir() -> Result<PathBuf, String> {
    known_folder(&FOLDERID_ProgramFiles)
}

fn inspect_engine(engine_dir: &Path) -> EngineDiagnostic {
    match fs::metadata(engine_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => EngineDiagnostic {
            installed: false,
            ready: false,
            issue: None,
        },
        Err(error) => EngineDiagnostic {
            installed: false,
            ready: false,
            issue: Some(format!("Не удалось открыть папку движка: {error}")),
        },
        Ok(metadata) if !metadata.is_dir() => EngineDiagnostic {
            installed: true,
            ready: false,
            issue: Some("Путь движка существует, но это не папка.".to_owned()),
        },
        Ok(_) => {
            let required_files = [
                engine_dir.join("bin").join("winws.exe"),
                engine_dir.join("bin").join("WinDivert.dll"),
                engine_dir.join("bin").join("WinDivert64.sys"),
                engine_dir.join("service.bat"),
            ];
            let missing: Vec<_> = required_files
                .iter()
                .filter(|path| !path.is_file())
                .map(|path| {
                    path.strip_prefix(engine_dir)
                        .unwrap_or(path)
                        .display()
                        .to_string()
                })
                .collect();
            let lists_present = engine_dir.join("lists").is_dir();
            let strategies_present = fs::read_dir(engine_dir)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .any(|entry| {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    name.starts_with("general") && name.ends_with(".bat") && entry.path().is_file()
                });
            if missing.is_empty() && lists_present && strategies_present {
                EngineDiagnostic {
                    installed: true,
                    ready: true,
                    issue: None,
                }
            } else {
                let mut reasons = missing;
                if !lists_present {
                    reasons.push("lists".to_owned());
                }
                if !strategies_present {
                    reasons.push("general*.bat".to_owned());
                }
                EngineDiagnostic {
                    installed: true,
                    ready: false,
                    issue: Some(format!("В папке движка отсутствуют необходимые элементы: {}. Это предварительная проверка структуры, а не проверка целостности релиза.", reasons.join(", "))),
                }
            }
        }
    }
}

fn inspect_service(name: &str, kind: ServiceKind) -> RawService {
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return service_query_error(format!(
            "Не удалось открыть диспетчер служб: {}",
            win_error()
        ));
    }
    let manager = ScHandle(manager);
    let service_name = to_wide(name);
    let service = unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_DOES_NOT_EXIST {
            return RawService {
                installed: false,
                state: "missing".to_owned(),
                process_id: None,
                executable_path: None,
                error: None,
            };
        }
        return service_query_error(format!(
            "Не удалось открыть службу {name}: код Windows {code}"
        ));
    }
    let service = ScHandle(service);
    let mut status: SERVICE_STATUS_PROCESS = unsafe { zeroed() };
    let mut bytes_needed = 0;
    let status_ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    };
    if status_ok == 0 {
        return RawService {
            installed: true,
            state: "error".to_owned(),
            process_id: None,
            executable_path: None,
            error: Some(format!(
                "Не удалось прочитать состояние службы {name}: {}",
                win_error()
            )),
        };
    }
    let state = if status.dwCurrentState == SERVICE_STOPPED && status.dwWin32ExitCode != 0 {
        "error".to_owned()
    } else {
        service_state(status.dwCurrentState).to_owned()
    };
    let (executable_path, config_error) = if matches!(kind, ServiceKind::Zapret) {
        match query_service_executable(&manager, &service_name) {
            Ok(path) => (path, None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };
    let status_error = (status.dwCurrentState == SERVICE_STOPPED && status.dwWin32ExitCode != 0)
        .then(|| {
            format!(
                "Служба {name} завершилась с кодом Windows {}",
                status.dwWin32ExitCode
            )
        });
    RawService {
        installed: true,
        state,
        process_id: (status.dwProcessId != 0).then_some(status.dwProcessId),
        executable_path,
        error: match (status_error, config_error) {
            (Some(status), Some(config)) => Some(format!("{status}; {config}")),
            (Some(status), None) => Some(status),
            (None, config) => config,
        },
    }
}

fn query_service_executable(
    manager: &ScHandle,
    service_name: &[u16],
) -> Result<Option<String>, String> {
    let service = unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_QUERY_CONFIG) };
    if service.is_null() {
        return Err(format!(
            "Не удалось прочитать конфигурацию службы: {}",
            win_error()
        ));
    }
    let service = ScHandle(service);
    let mut bytes_needed = 0;
    unsafe { QueryServiceConfigW(service.0, null_mut(), 0, &mut bytes_needed) };
    if bytes_needed == 0 || bytes_needed > 1024 * 1024 {
        return Err("Недопустимый размер конфигурации службы".to_owned());
    }
    let mut buffer = vec![0u64; (bytes_needed as usize).div_ceil(8)];
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    let ok = unsafe { QueryServiceConfigW(service.0, config, bytes_needed, &mut bytes_needed) };
    if ok == 0 {
        return Err(format!("Не удалось прочитать путь службы: {}", win_error()));
    }
    let raw = unsafe { (*config).lpBinaryPathName };
    if raw.is_null() {
        return Ok(None);
    }
    let command_line = unsafe { wide_ptr_to_string(raw) };
    Ok(executable_from_service_command(&command_line))
}

fn executable_from_service_command(command: &str) -> Option<String> {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_owned());
    }
    // Unquoted paths containing spaces are ambiguous under Windows service rules.
    let first = command.split_whitespace().next()?;
    if first.to_ascii_lowercase().ends_with(".exe") {
        Some(first.to_owned())
    } else {
        None
    }
}

fn read_service_strategy() -> Option<String> {
    let key = to_wide("SYSTEM\\CurrentControlSet\\Services\\zapret");
    let value = to_wide("zapret-discord-youtube");
    let mut bytes = 0;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            null_mut(),
            &mut bytes,
        )
    };
    if status != 0 || bytes < 2 || bytes > 8192 {
        return None;
    }
    let mut buffer = vec![0u16; (bytes as usize).div_ceil(2)];
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != 0 {
        return None;
    }
    let strategy = String::from_utf16_lossy(
        &buffer[..buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len())],
    );
    if strategy.is_empty() || strategy.len() > 256 || strategy.chars().any(char::is_control) {
        None
    } else {
        Some(strategy)
    }
}

fn inspect_windivert(engine_dir: &Path) -> WinDivertDiagnostic {
    let driver_file_present = ["WinDivert64.sys", "WinDivert32.sys"]
        .iter()
        .any(|name| engine_dir.join("bin").join(name).is_file());
    let candidates = ["WinDivert", "WinDivert14"];
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for name in candidates {
        let service = inspect_service(name, ServiceKind::WinDivert);
        if service.installed {
            found.push((name, service.state));
        }
        if let Some(error) = service.error {
            errors.push(error);
        }
    }
    let managed = if found.is_empty() {
        false
    } else {
        match crate::driver::managed_driver_status(engine_dir) {
            Ok(()) => errors.is_empty(),
            Err(error) => {
                errors.push(match error.detail {
                    Some(detail) => format!("{} {detail}", error.message),
                    None => error.message,
                });
                false
            }
        }
    };
    summarize_windivert(&found, &errors, managed, driver_file_present)
}

fn summarize_windivert(
    found: &[(&str, String)],
    errors: &[String],
    managed: bool,
    driver_file_present: bool,
) -> WinDivertDiagnostic {
    let selected = found
        .iter()
        .find(|(_, state)| state == "running")
        .or_else(|| found.iter().find(|(_, state)| state != "stopped"))
        .or_else(|| found.first());
    WinDivertDiagnostic {
        installed: !found.is_empty(),
        managed: managed && !found.is_empty() && errors.is_empty(),
        state: if errors.is_empty() {
            selected
                .map(|(_, state)| state.clone())
                .unwrap_or_else(|| "missing".into())
        } else {
            "unknown".into()
        },
        name: selected.map(|(name, _)| (*name).to_owned()),
        driver_file_present,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

fn inspect_winws_processes(
    managed_engine: Option<&Path>,
) -> (Vec<ProcessDiagnostic>, Option<String>) {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return (
            Vec::new(),
            Some(format!("Не удалось перечислить процессы: {}", win_error())),
        );
    }
    let snapshot = ProcessHandle(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut success = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    if success == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_NO_MORE_FILES {
            return (Vec::new(), None);
        }
        return (
            Vec::new(),
            Some(format!(
                "Не удалось прочитать список процессов: код Windows {code}"
            )),
        );
    }
    let mut processes = Vec::new();
    while success != 0 {
        let name = wide_array_to_string(&entry.szExeFile);
        if name.eq_ignore_ascii_case("winws.exe") {
            processes.push(inspect_winws_process(entry.th32ProcessID, managed_engine));
        }
        success = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    let code = unsafe { GetLastError() };
    let error = if code == ERROR_NO_MORE_FILES {
        None
    } else {
        Some(format!(
            "Список процессов прочитан не полностью: код Windows {code}"
        ))
    };
    processes.sort_by_key(|process| process.pid);
    (processes, error)
}

fn inspect_winws_process(pid: u32, managed_engine: Option<&Path>) -> ProcessDiagnostic {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return ProcessDiagnostic {
            pid,
            executable_path: None,
            managed: false,
            error: Some(format!(
                "Не удалось прочитать путь процесса: {}",
                win_error()
            )),
        };
    }
    let handle = ProcessHandle(handle);
    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return ProcessDiagnostic {
            pid,
            executable_path: None,
            managed: false,
            error: Some(format!(
                "Не удалось прочитать путь процесса: {}",
                win_error()
            )),
        };
    }
    let executable_path = PathBuf::from(OsString::from_wide(&buffer[..len as usize]));
    ProcessDiagnostic {
        pid,
        managed: is_managed_winws(&executable_path, managed_engine),
        executable_path: Some(display_path(&executable_path)),
        error: None,
    }
}

fn is_managed_winws(executable: &Path, managed_engine: Option<&Path>) -> bool {
    let Some(engine) = managed_engine else {
        return false;
    };
    let Ok(executable) = fs::canonicalize(executable) else {
        return false;
    };
    let managed_bin = engine.join("bin");
    executable
        .parent()
        .map(|parent| parent == managed_bin)
        .unwrap_or(false)
        && executable
            .file_name()
            .map(|name| name.eq_ignore_ascii_case("winws.exe"))
            .unwrap_or(false)
}

fn service_state(state: u32) -> &'static str {
    match state {
        SERVICE_RUNNING => "running",
        SERVICE_STOPPED => "stopped",
        SERVICE_START_PENDING
        | SERVICE_STOP_PENDING
        | SERVICE_CONTINUE_PENDING
        | SERVICE_PAUSE_PENDING => "pending",
        SERVICE_PAUSED => "unknown",
        _ => "unknown",
    }
}

fn service_query_error(error: String) -> RawService {
    RawService {
        installed: false,
        state: "unknown".to_owned(),
        process_id: None,
        executable_path: None,
        error: Some(error),
    }
}

fn win_error() -> String {
    std::io::Error::last_os_error().to_string()
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn wide_ptr_to_string(raw: *const u16) -> String {
    let mut len = 0;
    while *raw.add(len) != 0 && len < 32768 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(raw, len))
}

fn wide_array_to_string(raw: &[u16]) -> String {
    String::from_utf16_lossy(&raw[..raw.iter().position(|unit| *unit == 0).unwrap_or(raw.len())])
}

fn utc_now() -> String {
    let mut time: SYSTEMTIME = unsafe { zeroed() };
    unsafe { GetSystemTime(&mut time) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windivert_summary_never_hides_unknown_second_service() {
        let found = vec![("WinDivert", "running".into())];
        let known = summarize_windivert(&found, &[], true, true);
        assert!(known.managed);
        assert_eq!(known.state, "running");
        let unknown = summarize_windivert(&found, &["WinDivert14 inaccessible".into()], true, true);
        assert!(!unknown.managed);
        assert_eq!(unknown.state, "unknown");
        assert!(unknown.error.is_some());
        let external = summarize_windivert(&found, &[], false, true);
        assert!(!external.managed);
    }

    #[test]
    fn windivert_summary_prioritizes_unstable_driver_over_stopped_driver() {
        let found = vec![
            ("WinDivert", "stopped".into()),
            ("WinDivert14", "pending".into()),
        ];
        let snapshot = summarize_windivert(&found, &[], false, true);
        assert_eq!(snapshot.state, "pending");
        let missing = summarize_windivert(&[], &[], true, false);
        assert!(!missing.managed);
        assert!(!missing.installed);
        assert_eq!(missing.state, "missing");
    }

    #[test]
    fn collects_live_windows_snapshot_without_mutation() {
        let snapshot = collect().expect("Windows known folders must be available");
        assert!(snapshot.paths.config_dir.ends_with("ZapretGui\\config"));
        assert!(snapshot
            .paths
            .engine_dir
            .ends_with("ZapretGui\\engine\\current"));
        assert!(!snapshot.checked_at.is_empty());
    }

    #[test]
    fn service_command_path_parser_rejects_ambiguous_unquoted_paths() {
        assert_eq!(
            executable_from_service_command("\"C:\\Program Files\\ZapretGui\\winws.exe\" --foo"),
            Some("C:\\Program Files\\ZapretGui\\winws.exe".to_owned())
        );
        assert_eq!(
            executable_from_service_command("C:\\Program Files\\ZapretGui\\winws.exe --foo"),
            None
        );
    }

    #[test]
    fn path_ownership_requires_existing_canonical_engine_and_binary() {
        assert!(!is_managed_winws(
            Path::new("C:\\nonexistent\\bin\\winws.exe"),
            None
        ));
        let temp =
            std::env::temp_dir().join(format!("zapret-diagnostics-test-{}", std::process::id()));
        let engine = temp.join("engine").join("current");
        let bin = engine.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let executable = bin.join("winws.exe");
        fs::write(&executable, []).unwrap();
        let canonical_engine = fs::canonicalize(&engine).unwrap();
        assert!(is_managed_winws(&executable, Some(&canonical_engine)));
        assert!(!is_managed_winws(
            &bin.join("other.exe"),
            Some(&canonical_engine)
        ));
        fs::remove_file(&executable).unwrap();
        fs::remove_dir(&bin).unwrap();
        fs::remove_dir(&engine).unwrap();
        fs::remove_dir(temp.join("engine")).unwrap();
        fs::remove_dir(&temp).unwrap();
    }
}
