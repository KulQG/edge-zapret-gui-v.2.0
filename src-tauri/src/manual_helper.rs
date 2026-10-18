//! Elevated execution of an official strategy BAT on the normal desktop.
//! Only a strategy ID crosses IPC. A protected receipt records the exact
//! `winws.exe` child so closing the GUI never stops the engine.

use crate::error::AppError;
use crate::process::{ProcessState, ProcessStatus};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const VERSION: u8 = 2;
const MAX_FRAME: usize = 16 * 1024;
const IPC_WAIT: Duration = Duration::from_secs(70);
const LAUNCH_WAIT: Duration = Duration::from_secs(30);
const STOP_WAIT: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(25);
const RECEIPT_FILE: &str = "manual-process.json";

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    Start { version: u8, strategy_id: String },
    Stop { version: u8 },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Response {
    receipt: Option<Receipt>,
    stopped: bool,
    error: Option<AppError>,
    warning: Option<AppError>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    version: u8,
    pid: u32,
    creation_time_100ns: u64,
    executable_path: PathBuf,
    strategy_id: String,
    console_hidden: bool,
}

struct Handle(HANDLE);
unsafe impl Send for Handle {}
impl Handle {
    fn checked(value: HANDLE) -> Result<Self, AppError> {
        if value.is_null() || value == INVALID_HANDLE_VALUE {
            Err(os_failure())
        } else {
            Ok(Self(value))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub(crate) struct OperationLock(Handle);
impl Drop for OperationLock {
    fn drop(&mut self) {
        unsafe { ReleaseMutex(self.0 .0) };
    }
}

pub(crate) fn lock_operation() -> Result<OperationLock, AppError> {
    let handle = Handle::checked(unsafe {
        CreateMutexW(
            null(),
            0,
            wide("Local\\ZapretGui-Manual-Operation").as_ptr(),
        )
    })?;
    match unsafe { WaitForSingleObject(handle.0, 5_000) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED_0 => Ok(OperationLock(handle)),
        WAIT_TIMEOUT => Err(failure("Другая операция со стратегией ещё выполняется.")),
        _ => Err(os_failure()),
    }
}

pub(crate) fn start(strategy_id: &str) -> Result<ProcessStatus, AppError> {
    validate_strategy_id(strategy_id)?;
    let response = invoke(Request::Start {
        version: VERSION,
        strategy_id: strategy_id.to_owned(),
    })?;
    match (response.receipt, response.error) {
        (Some(receipt), None) if !response.stopped => {
            let mut status = running_status(&receipt);
            status.error = response.warning;
            Ok(status)
        }
        (_, Some(error)) => Err(error),
        _ => Err(failure("Помощник не подтвердил запуск стратегии.")),
    }
}

pub(crate) fn stop() -> Result<ProcessStatus, AppError> {
    let response = invoke(Request::Stop { version: VERSION })?;
    match (response.receipt, response.error) {
        (receipt, None) if response.stopped => Ok(stopped_status(receipt.as_ref())),
        (_, Some(error)) => Err(error),
        _ => Err(failure("Помощник не подтвердил остановку стратегии.")),
    }
}

pub(crate) fn status() -> ProcessStatus {
    match read_receipt() {
        Ok(None) => ProcessStatus::default(),
        Ok(Some(receipt)) => {
            match open_verified(&receipt, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE) {
                Ok(Some(_)) => running_status(&receipt),
                Ok(None) => stopped_status(Some(&receipt)),
                Err(error) => error_status(Some(&receipt), error),
            }
        }
        Err(error) => error_status(None, error),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OwnedIdentity {
    pub pid: u32,
    pub creation_time_100ns: u64,
    pub strategy_id: String,
}

/// Returns only an app-owned process whose persisted PID, creation time and
/// canonical executable path still match the live process.
pub(crate) fn owned_identity() -> Result<Option<OwnedIdentity>, AppError> {
    let Some(receipt) = read_receipt()? else {
        return Ok(None);
    };
    if open_verified(&receipt, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)?.is_none() {
        return Ok(None);
    }
    Ok(Some(OwnedIdentity {
        pid: receipt.pid,
        creation_time_100ns: receipt.creation_time_100ns,
        strategy_id: receipt.strategy_id,
    }))
}

pub(crate) fn exact_owned_matches(identity: &OwnedIdentity) -> Result<bool, AppError> {
    Ok(owned_identity()?.as_ref() == Some(identity))
}

pub(crate) fn run_helper() -> i32 {
    match helper_session() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn invoke(request: Request) -> Result<Response, AppError> {
    if elevated()? {
        return Ok(dispatch(request));
    }
    let app = crate::service_helper::verify_installed_app()?;
    let id = crate::service_helper::new_pipe_id()?;
    let pipe = Handle::checked(unsafe {
        CreateNamedPipeW(
            wide(&format!(r"\\.\pipe\ZapretGui-Manual-{id}")).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_FRAME as u32,
            MAX_FRAME as u32,
            0,
            null(),
        )
    })?;
    let helper = crate::service_helper::launch_manual_helper(&app, &id)?;
    crate::service_helper::connect_verified_helper(pipe.0, helper.0)?;
    set_nowait(pipe.0)?;
    send(pipe.0, &request)?;
    let response: Response = receive(pipe.0)?;
    if unsafe { WaitForSingleObject(helper.0, 5_000) } != WAIT_OBJECT_0 {
        return Err(failure("Помощник стратегии не завершился."));
    }
    Ok(response)
}

fn helper_session() -> Result<(), AppError> {
    let app = crate::service_helper::verify_installed_app()?;
    if !elevated()? {
        return Err(failure("Помощник не получил права администратора."));
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2
        || args[0] != "--manual-ipc"
        || !crate::service_helper::valid_pipe_id(&args[1])
    {
        return Err(failure("Неверные параметры помощника стратегии."));
    }
    let pipe = Handle::checked(unsafe {
        CreateFileW(
            wide(&format!(r"\\.\pipe\ZapretGui-Manual-{}", args[1])).as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    })?;
    set_nowait(pipe.0)?;
    let mut server_pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.0, &mut server_pid) } == 0 || server_pid == 0 {
        return Err(failure("Не удалось проверить основной процесс приложения."));
    }
    let parent = Handle::checked(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            server_pid,
        )
    })?;
    verify_parent(parent.0, &app)?;
    let request: Request = receive(pipe.0)?;
    send(pipe.0, &dispatch(request))
}

fn dispatch(request: Request) -> Response {
    let result = match request {
        Request::Start {
            version,
            strategy_id,
        } if version == VERSION => {
            elevated_start(&strategy_id).map(|(receipt, warning)| Response {
                receipt: Some(receipt),
                stopped: false,
                error: None,
                warning,
            })
        }
        Request::Stop { version } if version == VERSION => {
            elevated_stop().map(|receipt| Response {
                receipt,
                stopped: true,
                error: None,
                warning: None,
            })
        }
        _ => Err(failure("Неверная версия запроса помощника стратегии.")),
    };
    result.unwrap_or_else(|error| Response {
        receipt: None,
        stopped: false,
        error: Some(error),
        warning: None,
    })
}

fn elevated_start(strategy_id: &str) -> Result<(Receipt, Option<AppError>), AppError> {
    let _operation = lock_operation()?;
    validate_strategy_id(strategy_id)?;
    crate::storage_security::verify_engine_storage()?;
    if let Some(existing) = read_receipt()? {
        match open_verified(&existing, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)? {
            Some(_) => return Err(failure("Управляемая стратегия уже запущена.")),
            None => {}
        }
    }
    crate::check_manual_conflicts(None)?;
    let plan = crate::resolve_strategy(strategy_id)?;
    let current = crate::diagnostics::engine_dir()
        .map_err(|detail| failure("Папка движка недоступна.").with_detail(detail))?;
    crate::driver::verify_no_external_consumers(&current)?;
    let expected_winws = plan
        .executable_path
        .canonicalize()
        .map_err(|error| os_detail("Файл winws.exe недоступен.", error))?;
    let batch_directory = plan
        .batch_path
        .parent()
        .ok_or_else(|| failure("Папка стратегии недоступна."))?;
    let command = spawn_batch(&plan.batch_path, batch_directory)?;
    let cmd_pid = unsafe { GetProcessId(command.0) };
    let cmd_time = creation_time(command.0)?;
    let child = match await_child(cmd_pid, cmd_time, &expected_winws) {
        Ok(child) => child,
        Err(error) => {
            terminate_if_running(command.0);
            return Err(error);
        }
    };
    let pid = unsafe { GetProcessId(child.0) };
    let created = creation_time(child.0)?;
    let receipt = Receipt {
        version: VERSION,
        pid,
        creation_time_100ns: created,
        executable_path: expected_winws,
        strategy_id: plan.strategy_id,
        console_hidden: false,
    };
    let warning = hide_owned_console(&child, &receipt).err();
    if unsafe { WaitForSingleObject(child.0, 0) } != WAIT_TIMEOUT {
        return Err(failure("winws.exe завершился до подтверждения запуска."));
    }
    let mut receipt = receipt;
    receipt.console_hidden = warning.is_none();
    if let Err(error) = write_receipt(&receipt) {
        if matches!(
            open_verified(&receipt, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
            Ok(Some(_))
        ) {
            terminate_if_running(child.0);
        }
        terminate_if_running(command.0);
        return Err(error);
    }
    Ok((receipt, warning))
}

fn elevated_stop() -> Result<Option<Receipt>, AppError> {
    let _operation = lock_operation()?;
    crate::storage_security::verify_engine_storage()?;
    let Some(receipt) = read_receipt()? else {
        return Ok(None);
    };
    let Some(process) = open_verified(
        &receipt,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
    )?
    else {
        remove_receipt()?;
        return Ok(Some(receipt));
    };
    if unsafe { TerminateProcess(process.0, 1) } == 0 {
        if unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0 {
            remove_receipt()?;
            return Ok(Some(receipt));
        }
        return Err(os_failure());
    }
    if unsafe { WaitForSingleObject(process.0, STOP_WAIT.as_millis() as u32) } != WAIT_OBJECT_0 {
        return Err(failure("winws.exe не подтвердил остановку за пять секунд."));
    }
    remove_receipt()?;
    Ok(Some(receipt))
}

fn spawn_batch(batch: &Path, directory: &Path) -> Result<Handle, AppError> {
    let batch_arg = cmd_path(batch)?;
    let directory_arg = cmd_path(directory)?;
    // cmd expands percent variables inside quotes and treats these characters
    // specially. Reject an unusual managed-root path instead of reinterpreting it.
    if !cmd_safe_path(Path::new(&batch_arg)) {
        return Err(failure(
            "Путь к BAT содержит недопустимые символы для cmd.exe.",
        ));
    }
    let mut buffer = [0u16; 32_768];
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len >= buffer.len() {
        return Err(os_failure());
    }
    let cmd = PathBuf::from(OsString::from_wide(&buffer[..len])).join("cmd.exe");
    // /S strips the outer pair, leaving the BAT pathname quoted for cmd.
    let line = format!("\"{}\" /D /S /C \"\"{}\"\"", cmd.display(), batch_arg);
    let mut line = wide(&line);
    if line.len() > 32_767 {
        return Err(failure("Командная строка стратегии слишком длинная."));
    }
    let mut security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let input = Handle::checked(unsafe {
        CreateFileW(
            wide("NUL").as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &mut security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    })?;
    let output = Handle::checked(unsafe {
        CreateFileW(
            wide("NUL").as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &mut security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    })?;
    let desktop = wide("WinSta0\\Default");
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = desktop.as_ptr() as *mut u16;
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE as u16;
    startup.hStdInput = input.0;
    startup.hStdOutput = output.0;
    startup.hStdError = output.0;
    let mut result: PROCESS_INFORMATION = unsafe { zeroed() };
    if unsafe {
        CreateProcessW(
            wide_os(cmd.as_os_str()).as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_NO_WINDOW,
            null(),
            wide(&directory_arg).as_ptr(),
            &startup,
            &mut result,
        )
    } == 0
    {
        return Err(os_failure());
    }
    let thread_handle = Handle(result.hThread);
    drop(thread_handle);
    Ok(Handle(result.hProcess))
}

fn cmd_path(path: &Path) -> Result<String, AppError> {
    let raw = path
        .to_str()
        .ok_or_else(|| failure("Путь стратегии не подходит для cmd.exe."))?;
    let dos = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    let bytes = dos.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(failure("Путь стратегии не подходит для cmd.exe."));
    }
    Ok(dos.to_owned())
}

fn cmd_safe_path(path: &Path) -> bool {
    !path
        .to_string_lossy()
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '%' | '!' | '^' | '&' | '|' | '<' | '>' | '"'))
}

fn await_child(cmd_pid: u32, cmd_time: u64, expected: &Path) -> Result<Handle, AppError> {
    let deadline = Instant::now() + LAUNCH_WAIT;
    loop {
        let mut found: Option<Handle> = None;
        let snapshot = Handle::checked(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
        let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
        while more {
            if entry.th32ParentProcessID == cmd_pid && entry.th32ProcessID != 0 {
                if let Ok(handle) = Handle::checked(unsafe {
                    OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE,
                        0,
                        entry.th32ProcessID,
                    )
                }) {
                    if unsafe { WaitForSingleObject(handle.0, 0) } == WAIT_TIMEOUT
                        && creation_time(handle.0).is_ok_and(|value| value >= cmd_time)
                        && process_path(handle.0).is_ok_and(|path| same_path(&path, expected))
                    {
                        if found.is_some() {
                            return Err(failure(
                                "BAT запустил несколько winws.exe; владение неоднозначно.",
                            ));
                        }
                        found = Some(handle);
                    }
                }
            }
            more = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        }
        if let Some(handle) = found {
            return Ok(handle);
        }
        if Instant::now() >= deadline {
            return Err(failure(
                "Официальный BAT не запустил подтверждённый winws.exe.",
            ));
        }
        thread::sleep(TICK);
    }
}

struct Windows(Vec<HWND>);
unsafe extern "system" fn collect_window(hwnd: HWND, data: LPARAM) -> i32 {
    let windows = unsafe { &mut *(data as *mut Windows) };
    let mut class = [0u16; 64];
    let length = unsafe { GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32) };
    if length > 0 && String::from_utf16_lossy(&class[..length as usize]) == "ConsoleWindowClass" {
        windows.0.push(hwnd);
    }
    1
}

fn hide_owned_console(process: &Handle, receipt: &Receipt) -> Result<(), AppError> {
    let deadline = Instant::now() + LAUNCH_WAIT;
    loop {
        let mut windows = Windows(Vec::new());
        if unsafe { EnumWindows(Some(collect_window), &mut windows as *mut _ as LPARAM) } == 0 {
            return Err(os_failure());
        }
        let owned: Vec<HWND> = windows
            .0
            .into_iter()
            .filter(|hwnd| {
                let mut owner = 0;
                unsafe { GetWindowThreadProcessId(*hwnd, &mut owner) };
                owner == receipt.pid
            })
            .collect();
        if owned.len() > 1 {
            return Err(failure("У winws.exe найдено несколько окон консоли."));
        }
        if let Some(hwnd) = owned.first().copied() {
            if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT
                || creation_time(process.0)? != receipt.creation_time_100ns
                || !same_path(&process_path(process.0)?, &receipt.executable_path)
            {
                return Err(failure(
                    "Личность winws.exe изменилась перед скрытием окна.",
                ));
            }
            let mut owner = 0;
            unsafe { GetWindowThreadProcessId(hwnd, &mut owner) };
            if owner != receipt.pid || unsafe { IsWindow(hwnd) } == 0 {
                return Err(failure("Окно консоли изменилось перед скрытием."));
            }
            unsafe { ShowWindow(hwnd, SW_HIDE) };
            if unsafe { IsWindowVisible(hwnd) } == 0 {
                return Ok(());
            }
            return Err(failure("Не удалось скрыть консоль winws.exe."));
        }
        if Instant::now() >= deadline {
            return Err(failure("Окно запущенного winws.exe не найдено."));
        }
        thread::sleep(TICK);
    }
}

fn receipt_path() -> Result<PathBuf, AppError> {
    let current = crate::diagnostics::engine_dir()
        .map_err(|detail| failure("Папка движка недоступна.").with_detail(detail))?;
    let engine = current
        .parent()
        .ok_or_else(|| failure("Папка движка имеет неверный путь."))?;
    Ok(engine.join(RECEIPT_FILE))
}

fn read_receipt() -> Result<Option<Receipt>, AppError> {
    let path = receipt_path()?;
    if !path.exists() {
        return Ok(None);
    }
    crate::storage_security::verify_engine_storage()?;
    let metadata = fs::metadata(&path)
        .map_err(|error| os_detail("Не удалось прочитать запись запуска.", error))?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 {
        return Err(failure("Запись запуска повреждена."));
    }
    let bytes =
        fs::read(path).map_err(|error| os_detail("Не удалось прочитать запись запуска.", error))?;
    let receipt: Receipt =
        serde_json::from_slice(&bytes).map_err(|_| failure("Запись запуска повреждена."))?;
    validate_receipt(&receipt)?;
    Ok(Some(receipt))
}

fn write_receipt(receipt: &Receipt) -> Result<(), AppError> {
    let path = receipt_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| failure("Папка записи запуска недоступна."))?;
    crate::storage_security::verify_engine_storage()?;
    let temp = parent.join(format!(
        ".manual-process-{}.tmp",
        crate::service_helper::new_pipe_id()?
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| os_detail("Не удалось создать запись запуска.", error))?;
        let bytes = serde_json::to_vec(receipt)
            .map_err(|_| failure("Не удалось подготовить запись запуска."))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| os_detail("Не удалось сохранить запись запуска.", error))?;
        drop(file);
        if unsafe {
            MoveFileExW(
                wide_os(temp.as_os_str()).as_ptr(),
                wide_os(path.as_os_str()).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(os_failure());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn remove_receipt() -> Result<(), AppError> {
    let path = receipt_path()?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| os_detail("Не удалось удалить запись запуска.", error))?;
    }
    Ok(())
}

fn validate_receipt(receipt: &Receipt) -> Result<(), AppError> {
    validate_strategy_id(&receipt.strategy_id)?;
    if receipt.version != VERSION || receipt.pid == 0 || receipt.creation_time_100ns == 0 {
        return Err(failure("Запись запуска имеет неверные поля."));
    }
    let root = crate::diagnostics::engine_dir()
        .map_err(|detail| failure("Папка движка недоступна.").with_detail(detail))?;
    let expected = root
        .join("bin")
        .join("winws.exe")
        .canonicalize()
        .map_err(|error| os_detail("Не удалось проверить управляемый winws.exe.", error))?;
    if !same_path(&receipt.executable_path, &expected) {
        return Err(failure(
            "Запись запуска указывает на другой исполняемый файл.",
        ));
    }
    Ok(())
}

fn open_verified(receipt: &Receipt, access: u32) -> Result<Option<Handle>, AppError> {
    validate_receipt(receipt)?;
    let raw = unsafe { OpenProcess(access, 0, receipt.pid) };
    if raw.is_null() && unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
        return Ok(None);
    }
    let process = Handle::checked(raw)?;
    if unsafe { GetProcessId(process.0) } != receipt.pid {
        return Err(failure("PID процесса не совпадает с записью запуска."));
    }
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_OBJECT_0 => return Ok(None),
        WAIT_TIMEOUT => {}
        _ => return Err(os_failure()),
    }
    if creation_time(process.0)? != receipt.creation_time_100ns
        || !same_path(&process_path(process.0)?, &receipt.executable_path)
    {
        return Err(failure(
            "Запущенный процесс не совпадает с защищённой записью.",
        ));
    }
    Ok(Some(process))
}

fn process_path(handle: HANDLE) -> Result<PathBuf, AppError> {
    let mut buffer = [0u16; 32_768];
    let mut len = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) } == 0
        || len == 0
    {
        return Err(os_failure());
    }
    PathBuf::from(OsString::from_wide(&buffer[..len as usize]))
        .canonicalize()
        .map_err(|error| os_detail("Не удалось проверить путь процесса.", error))
}

fn creation_time(handle: HANDLE) -> Result<u64, AppError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(os_failure());
    }
    Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
}

fn running_status(receipt: &Receipt) -> ProcessStatus {
    ProcessStatus {
        state: ProcessState::Running,
        running: true,
        pid: Some(receipt.pid),
        strategy_id: Some(receipt.strategy_id.clone()),
        strategy_name: Some(receipt.strategy_id.clone()),
        executable_path: Some(receipt.executable_path.to_string_lossy().into_owned()),
        created_at_ms: Some(
            receipt
                .creation_time_100ns
                .saturating_sub(116_444_736_000_000_000)
                / 10_000,
        ),
        exit_code: None,
        error: if receipt.console_hidden {
            None
        } else {
            Some(failure(
                "Консоль winws.exe осталась видимой; стратегия продолжает работать.",
            ))
        },
    }
}

fn stopped_status(receipt: Option<&Receipt>) -> ProcessStatus {
    let mut status = ProcessStatus::default();
    if let Some(receipt) = receipt {
        status.pid = Some(receipt.pid);
        status.strategy_id = Some(receipt.strategy_id.clone());
        status.strategy_name = Some(receipt.strategy_id.clone());
        status.executable_path = Some(receipt.executable_path.to_string_lossy().into_owned());
    }
    status
}

fn error_status(receipt: Option<&Receipt>, error: AppError) -> ProcessStatus {
    let mut status = stopped_status(receipt);
    status.state = ProcessState::Error;
    status.error = Some(error);
    status
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn validate_strategy_id(value: &str) -> Result<(), AppError> {
    if value.is_empty()
        || value.len() > 128
        || !value.to_ascii_lowercase().starts_with("general")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" -_.()".contains(&byte))
    {
        Err(failure("Недопустимый идентификатор стратегии."))
    } else {
        Ok(())
    }
}

fn terminate_if_running(handle: HANDLE) {
    if unsafe { WaitForSingleObject(handle, 0) } == WAIT_TIMEOUT {
        unsafe { TerminateProcess(handle, 1) };
        unsafe { WaitForSingleObject(handle, STOP_WAIT.as_millis() as u32) };
    }
}

pub(crate) fn verify_parent(handle: HANDLE, installed: &Path) -> Result<(), AppError> {
    let path = process_path(handle)?;
    if !same_path(&path, installed) {
        return Err(failure("Канал создан другим приложением."));
    }
    crate::storage_security::verify_protected_path(&path)
}

pub(crate) fn elevated() -> Result<bool, AppError> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(os_failure());
    }
    let token = Handle(token);
    let mut info: TOKEN_ELEVATION = unsafe { zeroed() };
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            &mut info as *mut _ as _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(os_failure());
    }
    Ok(info.TokenIsElevated != 0)
}

fn set_nowait(pipe: HANDLE) -> Result<(), AppError> {
    let mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
    if unsafe { SetNamedPipeHandleState(pipe, &mode, null(), null()) } == 0 {
        Err(os_failure())
    } else {
        Ok(())
    }
}

fn send<T: Serialize>(pipe: HANDLE, value: &T) -> Result<(), AppError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| failure("Не удалось подготовить запрос помощника."))?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(failure("Запрос помощника слишком большой."));
    }
    let deadline = Instant::now() + IPC_WAIT;
    loop {
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
        if ok != 0 && written as usize == bytes.len() {
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        if (ok != 0 && written != 0)
            || (ok == 0 && !matches!(code, ERROR_NO_DATA | ERROR_PIPE_BUSY))
        {
            return Err(os_failure());
        }
        pause(deadline)?;
    }
}

fn receive<T: for<'de> Deserialize<'de>>(pipe: HANDLE) -> Result<T, AppError> {
    let deadline = Instant::now() + IPC_WAIT;
    loop {
        let mut available = 0;
        if unsafe { PeekNamedPipe(pipe, null_mut(), 0, null_mut(), &mut available, null_mut()) }
            == 0
        {
            return Err(os_failure());
        }
        if available > MAX_FRAME as u32 {
            return Err(failure("Ответ помощника слишком большой."));
        }
        if available != 0 {
            let mut bytes = vec![0u8; MAX_FRAME];
            let mut read = 0;
            if unsafe {
                ReadFile(
                    pipe,
                    bytes.as_mut_ptr(),
                    bytes.len() as u32,
                    &mut read,
                    null_mut(),
                )
            } == 0
                || read == 0
            {
                return Err(os_failure());
            }
            return serde_json::from_slice(&bytes[..read as usize])
                .map_err(|_| failure("Ответ помощника повреждён."));
        }
        pause(deadline)?;
    }
}

fn pause(deadline: Instant) -> Result<(), AppError> {
    if Instant::now() >= deadline {
        Err(failure("Истекло время ответа помощника."))
    } else {
        thread::sleep(TICK);
        Ok(())
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}
fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn failure(message: &'static str) -> AppError {
    AppError::new("manual_helper_failed", message, "Проверьте состояние движка и повторите действие. При запросе Windows подтвердите права администратора.")
}
fn os_failure() -> AppError {
    failure("Операция Windows не выполнена.")
        .with_detail(std::io::Error::last_os_error().to_string())
}
fn os_detail(message: &'static str, error: std::io::Error) -> AppError {
    failure(message).with_detail(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_ids_cannot_be_paths_or_shell_commands() {
        assert!(validate_strategy_id("general (FAKE TLS AUTO ALT2)").is_ok());
        for bad in [
            "../general",
            "general&del",
            "general\\x",
            "general%PATH%",
            "service",
        ] {
            assert!(validate_strategy_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cmd_path_rejects_expansion_and_metacharacters() {
        assert_eq!(
            cmd_path(Path::new(
                r"\\?\C:\ProgramData\ZapretGui\engine\current\general (ALT2).bat"
            ))
            .unwrap(),
            r"C:\ProgramData\ZapretGui\engine\current\general (ALT2).bat"
        );
        assert!(cmd_path(Path::new(r"\\?\Volume{1234}\general.bat")).is_err());
        assert!(cmd_safe_path(Path::new(
            r"C:\ProgramData\ZapretGui\engine\current\general (ALT2).bat"
        )));
        for path in [
            r"C:\engine\%TEMP%\general.bat",
            r"C:\engine&other\general.bat",
        ] {
            assert!(!cmd_safe_path(Path::new(path)));
        }
    }

    #[test]
    fn receipt_rejects_missing_identity() {
        let receipt = Receipt {
            version: VERSION,
            pid: 0,
            creation_time_100ns: 1,
            executable_path: PathBuf::from(
                r"C:\ProgramData\ZapretGui\engine\current\bin\winws.exe",
            ),
            strategy_id: "general".into(),
            console_hidden: false,
        };
        assert!(validate_receipt(&receipt).is_err());
    }
}
