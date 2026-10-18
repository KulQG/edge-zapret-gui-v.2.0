//! One-shot request channel to the GUI-subsystem helper elevated through UAC.

use crate::engine_update::{self, EngineUpdateProgress, EngineUpdateResult, SelectedStrategy};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_CANCELLED, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_LISTENING, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Com::CoCreateGuid;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, SetNamedPipeHandleState,
    PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetProcessId, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

const PIPE_BUFFER_BYTES: usize = 16 * 1024;
const HELPER_VERB: &str = "runas";
const HELPER_SWITCH: &str = "--ipc";
const PROTOCOL_VERSION: u8 = 1;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateHelperRequest {
    kind: String,
    protocol_version: u8,
    operation_id: String,
    selected_strategy: Option<SelectedStrategy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum UpdateFrame {
    Progress {
        progress: EngineUpdateProgress,
    },
    Finished {
        result: Option<EngineUpdateResult>,
        error: Option<AppError>,
    },
}

pub(crate) fn invoke_elevated_update<F>(
    kind: &str,
    operation_id: &str,
    selected_strategy: Option<SelectedStrategy>,
    mut on_progress: F,
) -> Result<EngineUpdateResult, AppError>
where
    F: FnMut(EngineUpdateProgress),
{
    if !matches!(kind, "update" | "rollback") {
        return Err(helper_error(
            "Действие обновления не поддерживается.",
            kind.to_owned(),
        ));
    }
    let id = new_pipe_id()?;
    let pipe_wide = wide(&pipe_name(&id));
    let server = unsafe {
        CreateNamedPipeW(
            pipe_wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER_BYTES as u32,
            PIPE_BUFFER_BYTES as u32,
            0,
            null(),
        )
    };
    if server == INVALID_HANDLE_VALUE {
        return Err(helper_error(
            "Не удалось открыть защищённый канал обновления.",
            last_error(),
        ));
    }
    let server = Handle(server);
    let helper_path = locate_helper()?;
    let elevated_process = launch_helper(&helper_path, &id)?;
    connect_verified_helper(server.0, elevated_process.0)?;
    let request = UpdateHelperRequest {
        kind: kind.to_owned(),
        protocol_version: PROTOCOL_VERSION,
        operation_id: operation_id.to_owned(),
        selected_strategy,
    };
    let bytes = serde_json::to_vec(&request).map_err(|_| {
        helper_error(
            "Не удалось подготовить запрос обновления.",
            "Ошибка формата запроса.".into(),
        )
    })?;
    write_message(server.0, &bytes)?;

    loop {
        let bytes = read_message(server.0)?;
        let frame: UpdateFrame = serde_json::from_slice(&bytes).map_err(|_| {
            helper_error(
                "Помощник обновления вернул неверный ответ.",
                "Ошибка формата IPC.".to_owned(),
            )
        })?;
        match frame {
            UpdateFrame::Progress { progress } => on_progress(progress),
            UpdateFrame::Finished { result, error } => {
                let wait = unsafe { WaitForSingleObject(elevated_process.0, 35_000) };
                if wait != WAIT_OBJECT_0 {
                    return Err(helper_error(
                        "Повышенный помощник не завершился после обновления.",
                        format!("Код Windows ожидания {wait}"),
                    ));
                }
                return match (result, error) {
                    (Some(result), None) => Ok(result),
                    (None, Some(error)) => Err(error),
                    _ => Err(helper_error(
                        "Помощник вернул неполный результат обновления.",
                        "Ответ должен содержать результат или ошибку.".to_owned(),
                    )),
                };
            }
        }
    }
}

/// Entry point used by the same GUI-subsystem application when restarted through UAC.
pub fn run_helper() -> i32 {
    if verify_installed_app().is_err() {
        return 2;
    }
    let mut args = std::env::args();
    let _program = args.next();
    if args.next().as_deref() != Some(HELPER_SWITCH) {
        return 2;
    }
    let Some(id) = args.next() else { return 2 };
    if args.next().is_some() || !valid_pipe_id(&id) {
        return 2;
    }

    let Some(pipe) = connect_pipe(&pipe_name(&id)) else {
        return 3;
    };
    let request_bytes = match read_message(pipe.0) {
        Ok(bytes) => bytes,
        Err(_) => return 3,
    };
    run_update_helper(pipe.0, &request_bytes)
}

fn run_update_helper(pipe: HANDLE, bytes: &[u8]) -> i32 {
    let response = (|| {
        let request: UpdateHelperRequest = serde_json::from_slice(bytes).map_err(|_| {
            helper_error(
                "Запрос обновления повреждён.",
                "Проверьте версию приложения.".into(),
            )
        })?;
        if !matches!(request.kind.as_str(), "update" | "rollback")
            || request.protocol_version != PROTOCOL_VERSION
        {
            return Err(helper_error(
                "Версия запроса обновления не поддерживается.",
                request.protocol_version.to_string(),
            ));
        }
        let _trusted_helper = locate_helper()?;
        crate::storage_security::prepare_engine_storage()?;
        let report = |progress| {
            let frame = UpdateFrame::Progress { progress };
            if let Ok(bytes) = serde_json::to_vec(&frame) {
                let _ = write_message(pipe, &bytes);
            }
        };
        if request.kind == "rollback" {
            engine_update::rollback_retained(&request.operation_id, report)
        } else {
            engine_update::execute(&request.operation_id, request.selected_strategy, report)
        }
    })();
    let frame = match response {
        Ok(result) => UpdateFrame::Finished {
            result: Some(result),
            error: None,
        },
        Err(error) => UpdateFrame::Finished {
            result: None,
            error: Some(error),
        },
    };
    let Ok(bytes) = serde_json::to_vec(&frame) else {
        return 5;
    };
    if write_message(pipe, &bytes).is_err() {
        5
    } else if matches!(frame, UpdateFrame::Finished { error: None, .. }) {
        0
    } else {
        1
    }
}

fn launch_helper(path: &Path, pipe_id: &str) -> Result<Handle, AppError> {
    launch_fixed_helper(path, pipe_id, HELPER_SWITCH)
}

pub(crate) fn launch_manual_helper(path: &Path, pipe_id: &str) -> Result<Handle, AppError> {
    launch_fixed_helper(path, pipe_id, "--manual-ipc")
}

pub(crate) fn launch_scan_helper(path: &Path, pipe_id: &str) -> Result<Handle, AppError> {
    launch_fixed_helper(path, pipe_id, "--scan-ipc")
}

fn launch_fixed_helper(path: &Path, pipe_id: &str, switch: &str) -> Result<Handle, AppError> {
    let path = wide_os(path.as_os_str());
    let verb = wide(HELPER_VERB);
    let parameters = wide(&format!("{switch} {pipe_id}"));
    let mut info: SHELLEXECUTEINFOW = unsafe { zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = path.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.lpDirectory = null();
    info.nShow = SW_HIDE;
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_CANCELLED {
            return Err(AppError::new(
                "uac_cancelled",
                "Запрос прав администратора отменён.",
                "Повторите действие и подтвердите стандартный запрос Windows.",
            ));
        }
        return Err(helper_error(
            "Windows не смогла запустить повышенный помощник.",
            format!("Код Windows {code}"),
        ));
    }
    if info.hProcess.is_null() {
        return Err(helper_error(
            "Windows не вернула дескриптор повышенного помощника.",
            "ShellExecuteExW не предоставила процесс для ожидания.".into(),
        ));
    }
    Ok(Handle(info.hProcess))
}

pub(crate) fn verify_installed_app() -> Result<PathBuf, AppError> {
    locate_helper()
}

fn locate_helper() -> Result<PathBuf, AppError> {
    let app = std::env::current_exe()
        .map_err(|error| helper_error("Не удалось определить приложение.", error.to_string()))?;
    let app = app.canonicalize().map_err(|error| {
        helper_error(
            "Не удалось проверить файл приложения для UAC.",
            error.to_string(),
        )
    })?;
    let protected_root = crate::diagnostics::program_files_dir()
        .and_then(|path| path.canonicalize().map_err(|error| error.to_string()))
        .map_err(|detail| {
            helper_error(
                "Не удалось проверить папку установленного приложения.",
                detail,
            )
        })?;
    if !app.starts_with(&protected_root) {
        return Err(helper_error(
            "Для безопасного запроса UAC требуется установленное приложение.",
            format!(
                "Помощник находится в {}, а защищённая папка Program Files — {}.",
                app.display(),
                protected_root.display()
            ),
        ));
    }
    crate::storage_security::verify_protected_path(&app)?;
    Ok(app)
}

pub(crate) fn new_pipe_id() -> Result<String, AppError> {
    let mut guid = windows_sys::core::GUID::default();
    let result = unsafe { CoCreateGuid(&mut guid) };
    if result < 0 {
        return Err(helper_error(
            "Не удалось создать защищённый идентификатор запроса.",
            format!("Код Windows 0x{:08X}", result as u32),
        ));
    }
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    ))
}

pub(crate) fn valid_pipe_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn pipe_name(id: &str) -> String {
    format!(r"\\.\pipe\ZapretGui-Service-{id}")
}

/// Nonblocking mode is used only while accepting the connection. Message I/O
/// stays synchronous after a verified connection, without a detached wait thread.
pub(crate) fn connect_verified_helper(pipe: HANDLE, helper: HANDLE) -> Result<(), AppError> {
    let expected_pid = unsafe { GetProcessId(helper) };
    if expected_pid == 0 {
        return Err(helper_error(
            "Не удалось проверить процесс помощника.",
            last_error(),
        ));
    }
    let started = Instant::now();
    loop {
        let connected = unsafe { ConnectNamedPipe(pipe, null_mut()) };
        if connected == 0 {
            let code = unsafe { GetLastError() };
            match code {
                ERROR_PIPE_CONNECTED => break,
                ERROR_PIPE_LISTENING => {}
                ERROR_NO_DATA => {
                    return Err(helper_error(
                        "Помощник отключился до передачи запроса.",
                        "Соединение закрыто; повторите действие.".to_owned(),
                    ));
                }
                _ => {
                    return Err(helper_error(
                        "Не удалось подключить повышенный помощник.",
                        format!("Код Windows {code}"),
                    ));
                }
            }
        }
        // A successful nonblocking ConnectNamedPipe makes a disconnected pipe
        // available; only ERROR_PIPE_CONNECTED confirms an actual client.
        if started.elapsed() >= CONNECT_TIMEOUT {
            return Err(helper_error(
                "Истекло время подключения повышенного помощника.",
                "Помощник не подключился за 15 секунд после запроса UAC.".to_owned(),
            ));
        }
        match unsafe { WaitForSingleObject(helper, 50) } {
            WAIT_TIMEOUT => {}
            WAIT_OBJECT_0 => {
                return Err(helper_error(
                    "Повышенный помощник завершился до подключения.",
                    "Проверьте журнал и повторите действие.".to_owned(),
                ));
            }
            _ => {
                return Err(helper_error(
                    "Не удалось дождаться повышенного помощника.",
                    last_error(),
                ));
            }
        }
    }
    let mut peer_pid = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut peer_pid) } == 0 || peer_pid != expected_pid
    {
        return Err(helper_error(
            "К каналу подключился неподтверждённый процесс.",
            format!("Ожидался PID {expected_pid}; получен PID {peer_pid}. Запрос не передан."),
        ));
    }
    let mode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    if unsafe { SetNamedPipeHandleState(pipe, &mode, null(), null()) } == 0 {
        return Err(helper_error(
            "Не удалось настроить защищённый канал помощника.",
            last_error(),
        ));
    }
    Ok(())
}

pub(crate) fn connect_pipe(name: &str) -> Option<Handle> {
    let name = wide(name);
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            windows_sys::Win32::Foundation::GENERIC_READ
                | windows_sys::Win32::Foundation::GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }
    let handle = Handle(handle);
    let mode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    if unsafe { SetNamedPipeHandleState(handle.0, &mode, null(), null()) } == 0 {
        return None;
    }
    Some(handle)
}

pub(crate) fn write_message(pipe: HANDLE, bytes: &[u8]) -> Result<(), AppError> {
    let mut written = 0;
    let ok = unsafe {
        WriteFile(
            pipe,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            null_mut(),
        )
    };
    if ok == 0 || written as usize != bytes.len() {
        return Err(helper_error(
            "Не удалось передать запрос помощнику.",
            last_error(),
        ));
    }
    Ok(())
}

pub(crate) fn read_message(pipe: HANDLE) -> Result<Vec<u8>, AppError> {
    let mut bytes = vec![0; PIPE_BUFFER_BYTES];
    let mut read = 0;
    let ok = unsafe {
        ReadFile(
            pipe,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            &mut read,
            null_mut(),
        )
    };
    if ok == 0 || read == 0 || read as usize > bytes.len() {
        return Err(helper_error(
            "Не удалось получить ответ помощника.",
            last_error(),
        ));
    }
    bytes.truncate(read as usize);
    Ok(bytes)
}

fn helper_error(message: &'static str, detail: String) -> AppError {
    AppError::new(
        "service_helper_failed",
        message,
        "Повторите действие с правами администратора.",
    )
    .with_detail(detail)
}

fn last_error() -> String {
    format!("Код Windows {}", unsafe { GetLastError() })
}

pub(crate) fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

pub(crate) struct Handle(pub(crate) HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}
