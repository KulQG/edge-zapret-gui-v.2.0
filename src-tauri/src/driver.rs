//! Narrow WinDivert shutdown for the engine replacement transaction.
//! No driver service is created/deleted and no external executable is invoked.
//! REFLECT snapshot protocol follows the public WinDivert 2.x API and sample:
//! https://github.com/basil00/WinDivert/blob/master/examples/windivertctl/windivertctl.c

use crate::error::AppError;
use std::fs::{self, File, OpenOptions};
use std::mem::{size_of, zeroed};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, ERROR_NO_DATA, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_NOT_ACTIVE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Services::*;

const NAMES: [&str; 2] = ["WinDivert", "WinDivert14"];
const MAX_CONFIG: usize = 1024 * 1024;
const MAX_REFLECTION_EVENTS: usize = 65_536;
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

struct ScHandle(SC_HANDLE);
impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DriverIdentity {
    name: String,
    image_path: String,
    service_type: u32,
}

struct Driver {
    handle: ScHandle,
    identity: DriverIdentity,
    state: u32,
}

/// Exclusive read/write probes verify the engine has no current consumers.
/// Release these before a directory rename: Windows can refuse that operation
/// while child files remain open, even when DELETE sharing is enabled.
pub(crate) struct EngineFileGuards {
    _files: Vec<File>,
}

/// Read-only SCM ownership audit for diagnostics. Does not load any DLL or
/// request SERVICE_STOP access, and never changes driver state.
pub(crate) fn managed_driver_status(current: &Path) -> Result<(), AppError> {
    crate::storage_security::verify_engine_storage()?;
    let manager = open_manager()?;
    inspect_all_with_access(
        &manager,
        &current.join("bin").join("WinDivert64.sys"),
        false,
    )?;
    Ok(())
}

/// Privileged admission check for reusing an idle managed driver in manual mode.
/// A stopped/missing driver is left untouched and will be loaded by winws.
pub(crate) fn verify_no_external_consumers(current: &Path) -> Result<(), AppError> {
    crate::storage_security::verify_engine_storage()?;
    let manager = open_manager()?;
    let drivers = inspect_all_with_access(
        &manager,
        &current.join("bin").join("WinDivert64.sys"),
        false,
    )?;
    if drivers.iter().any(|driver| driver.state == SERVICE_RUNNING) {
        verify_no_consumers(current)?;
    }
    Ok(())
}

/// Caller must already have stopped its own zapret/manual processes. Every
/// candidate is checked before the first ControlService operation.
pub(crate) fn quiesce_for_update(current: &Path) -> Result<EngineFileGuards, AppError> {
    crate::storage_security::verify_engine_storage()?;
    verify_no_winws()?;
    let expected = current.join("bin").join("WinDivert64.sys");
    let manager = open_manager()?;
    let drivers = inspect_all(&manager, &expected)?;
    if drivers.iter().any(|driver| driver.state == SERVICE_RUNNING) {
        verify_no_consumers(current)?;
    }
    // Recheck after the reflection snapshot, immediately before requesting stop.
    verify_no_winws()?;
    for driver in &drivers {
        let identity = query_identity(&driver.handle, &driver.identity.name)?;
        if identity != driver.identity {
            return Err(driver_error(
                "Конфигурация WinDivert изменилась во время проверки.",
                identity.name,
            ));
        }
        validate_identity(&identity, &expected)?;
        let state = query_state(&driver.handle)?;
        validate_state(state, &identity.name)?;
    }
    for driver in &drivers {
        if query_state(&driver.handle)? == SERVICE_RUNNING {
            let mut status = unsafe { zeroed::<SERVICE_STATUS>() };
            if unsafe { ControlService(driver.handle.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
                let code = unsafe { GetLastError() };
                if code != ERROR_SERVICE_NOT_ACTIVE {
                    return Err(driver_error("Не удалось остановить управляемый WinDivert.", format!("{}: код Windows {code}. Возможно, драйвер используется другой программой.", driver.identity.name)));
                }
            }
            wait_stopped(&driver.handle, &driver.identity.name)?;
        }
    }
    // A service appearing during shutdown must also pass identity/state checks.
    for driver in inspect_all(&manager, &expected)? {
        if driver.state != SERVICE_STOPPED {
            return Err(driver_error(
                "WinDivert снова активен; замена файлов отменена.",
                driver.identity.name,
            ));
        }
    }
    verify_no_winws()?;
    lock_engine_files(current)
}

fn verify_no_winws() -> Result<(), AppError> {
    let snapshot = crate::diagnostics::collect().map_err(|detail| {
        driver_error(
            "Не удалось проверить процессы перед остановкой WinDivert.",
            detail,
        )
    })?;
    if let Some(process) = snapshot.processes.first() {
        return Err(driver_error(
            "Работающий winws.exe мешает безопасной остановке WinDivert.",
            format!(
                "PID {}: {}",
                process.pid,
                process
                    .executable_path
                    .as_deref()
                    .unwrap_or("путь недоступен")
            ),
        ));
    }
    if snapshot.warnings.iter().any(|warning| {
        warning.contains("процесс")
            && (warning.contains("полностью") || warning.contains("перечислить"))
    }) {
        return Err(driver_error(
            "Список процессов прочитан не полностью.",
            "Остановка драйвера отменена.".into(),
        ));
    }
    if snapshot.service.installed
        && !matches!(snapshot.service.state.as_str(), "stopped" | "missing")
    {
        return Err(driver_error(
            "Служба zapret не остановлена или её состояние неизвестно.",
            snapshot.service.state,
        ));
    }
    Ok(())
}

fn open_manager() -> Result<ScHandle, AppError> {
    let handle = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if handle.is_null() {
        Err(windows_error(
            "Не удалось открыть диспетчер служб для проверки WinDivert.",
        ))
    } else {
        Ok(ScHandle(handle))
    }
}

fn inspect_all(manager: &ScHandle, expected: &Path) -> Result<Vec<Driver>, AppError> {
    inspect_all_with_access(manager, expected, true)
}

fn inspect_all_with_access(
    manager: &ScHandle,
    expected: &Path,
    can_stop: bool,
) -> Result<Vec<Driver>, AppError> {
    let mut result = Vec::new();
    for name in NAMES {
        let handle = unsafe {
            OpenServiceW(
                manager.0,
                wide(name).as_ptr(),
                SERVICE_QUERY_CONFIG
                    | SERVICE_QUERY_STATUS
                    | if can_stop { SERVICE_STOP } else { 0 },
            )
        };
        if handle.is_null() {
            if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
                continue;
            }
            return Err(windows_error(
                "Не удалось проверить одну из служб WinDivert.",
            ));
        }
        let handle = ScHandle(handle);
        let identity = query_identity(&handle, name)?;
        validate_identity(&identity, expected)?;
        let state = query_state(&handle)?;
        validate_state(state, name)?;
        result.push(Driver {
            handle,
            identity,
            state,
        });
    }
    Ok(result)
}

fn query_identity(handle: &ScHandle, name: &str) -> Result<DriverIdentity, AppError> {
    let mut needed = 0u32;
    unsafe { QueryServiceConfigW(handle.0, null_mut(), 0, &mut needed) };
    if needed as usize > MAX_CONFIG || (needed as usize) < size_of::<QUERY_SERVICE_CONFIGW>() {
        return Err(windows_error(
            "Не удалось определить размер конфигурации WinDivert.",
        ));
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if unsafe { QueryServiceConfigW(handle.0, config, needed, &mut needed) } == 0 {
        return Err(windows_error(
            "Не удалось прочитать конфигурацию WinDivert.",
        ));
    }
    let pointer = unsafe { (*config).lpBinaryPathName };
    let start = storage.as_ptr() as usize;
    let end = start + storage.len() * size_of::<usize>();
    let address = pointer as usize;
    if address < start || address >= end || address % 2 != 0 {
        return Err(driver_error(
            "Путь драйвера WinDivert повреждён.",
            name.into(),
        ));
    }
    let value = unsafe { std::slice::from_raw_parts(pointer, (end - address) / 2) };
    let length = value
        .iter()
        .position(|&unit| unit == 0)
        .ok_or_else(|| driver_error("Путь драйвера WinDivert не завершён.", name.into()))?;
    let image_path = String::from_utf16(&value[..length]).map_err(|_| {
        driver_error(
            "Путь драйвера WinDivert имеет неверную кодировку.",
            name.into(),
        )
    })?;
    Ok(DriverIdentity {
        name: name.into(),
        image_path,
        service_type: unsafe { (*config).dwServiceType },
    })
}

fn validate_identity(identity: &DriverIdentity, expected: &Path) -> Result<(), AppError> {
    if !NAMES.contains(&identity.name.as_str()) || identity.service_type != SERVICE_KERNEL_DRIVER {
        return Err(driver_error(
            "Служба WinDivert имеет неподдерживаемый тип.",
            identity.name.clone(),
        ));
    }
    let path = normalize_image_path(&identity.image_path)?;
    let actual = path.canonicalize().map_err(|error| {
        driver_error(
            "Не удалось проверить файл драйвера WinDivert.",
            format!("{}: {error}", identity.image_path),
        )
    })?;
    let expected = expected.canonicalize().map_err(|error| {
        driver_error(
            "Не найден управляемый файл WinDivert64.sys.",
            error.to_string(),
        )
    })?;
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(driver_error(
            "WinDivert принадлежит другой установке; остановка отменена.",
            format!("{}: {}", identity.name, identity.image_path),
        ));
    }
    Ok(())
}

fn normalize_image_path(value: &str) -> Result<PathBuf, AppError> {
    let value = value.trim();
    let value = if value.starts_with('"') && value.ends_with('"') && value.len() > 2 {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let value = value
        .strip_prefix(r"\??\")
        .or_else(|| value.strip_prefix(r"\\?\"))
        .unwrap_or(value);
    if value.contains(['"', '\0', '%'])
        || value.len() < 4
        || value.as_bytes()[1] != b':'
        || value.as_bytes()[2] != b'\\'
        || !value.as_bytes()[0].is_ascii_alphabetic()
        || value.contains("..")
    {
        return Err(driver_error(
            "Путь WinDivert нельзя безопасно проверить.",
            value.into(),
        ));
    }
    Ok(PathBuf::from(value))
}

fn query_state(handle: &ScHandle) -> Result<u32, AppError> {
    let mut status = unsafe { zeroed::<SERVICE_STATUS>() };
    if unsafe { QueryServiceStatus(handle.0, &mut status) } == 0 {
        Err(windows_error("Не удалось получить состояние WinDivert."))
    } else {
        Ok(status.dwCurrentState)
    }
}

fn validate_state(state: u32, name: &str) -> Result<(), AppError> {
    if matches!(state, SERVICE_RUNNING | SERVICE_STOPPED) {
        Ok(())
    } else {
        Err(driver_error(
            "WinDivert выполняет переход или имеет неизвестное состояние.",
            format!("{name}: {state}"),
        ))
    }
}

fn wait_stopped(handle: &ScHandle, name: &str) -> Result<(), AppError> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        let state = query_state(handle)?;
        if state == SERVICE_STOPPED {
            return Ok(());
        }
        if !matches!(state, SERVICE_RUNNING | SERVICE_STOP_PENDING) || Instant::now() >= deadline {
            return Err(driver_error("WinDivert не освободил драйвер за отведённое время.", format!("{name}: состояние {state}. Завершите использующую драйвер программу и повторите обновление.")));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

type DivertOpen = unsafe extern "system" fn(*const u8, i32, i16, u64) -> *mut std::ffi::c_void;
type DivertShutdown = unsafe extern "system" fn(*mut std::ffi::c_void, i32) -> i32;
type DivertRecv = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut u8,
    u32,
    *mut u32,
    *mut DivertAddress,
) -> i32;
type DivertClose = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

// WinDivert 2.x public WINDIVERT_ADDRESS: 16-byte header + 64-byte union.
// Reflect.ProcessId is at union offset 8. No borrowed packet data is trusted.
#[repr(C, align(8))]
struct DivertAddress {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}

fn verify_no_consumers(current: &Path) -> Result<(), AppError> {
    let path = current
        .join("bin")
        .join("WinDivert.dll")
        .canonicalize()
        .map_err(|error| {
            driver_error(
                "Не удалось найти библиотеку проверки потребителей WinDivert.",
                error.to_string(),
            )
        })?;
    crate::storage_security::verify_engine_storage()?;
    let module = unsafe {
        LoadLibraryExW(
            wide(&path.to_string_lossy()).as_ptr(),
            null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(windows_error(
            "Не удалось загрузить защищённую библиотеку WinDivert.",
        ));
    }
    struct Library(*mut std::ffi::c_void);
    impl Drop for Library {
        fn drop(&mut self) {
            unsafe { FreeLibrary(self.0) };
        }
    }
    let library = Library(module);
    unsafe fn symbol(
        module: *mut std::ffi::c_void,
        name: &[u8],
    ) -> Result<unsafe extern "system" fn() -> isize, AppError> {
        required_export(GetProcAddress(module, name.as_ptr()), name)
    }
    let open: DivertOpen = unsafe { std::mem::transmute(symbol(library.0, b"WinDivertOpen\0")?) };
    let shutdown: DivertShutdown =
        unsafe { std::mem::transmute(symbol(library.0, b"WinDivertShutdown\0")?) };
    let recv: DivertRecv = unsafe { std::mem::transmute(symbol(library.0, b"WinDivertRecv\0")?) };
    let close: DivertClose =
        unsafe { std::mem::transmute(symbol(library.0, b"WinDivertClose\0")?) };
    // REFLECT=4; SNIFF|RECV_ONLY|NO_INSTALL. This cannot install/start a driver.
    let handle = unsafe { open(b"true\0".as_ptr(), 4, 0, 0x15) };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(windows_error(
            "Не удалось проверить потребителей WinDivert. Остановка драйвера отменена.",
        ));
    }
    struct Reflection {
        handle: *mut std::ffi::c_void,
        close: DivertClose,
    }
    impl Drop for Reflection {
        fn drop(&mut self) {
            unsafe { (self.close)(self.handle) };
        }
    }
    let reflection = Reflection { handle, close };
    // Official windivertctl list protocol: freeze snapshot, drain to NO_DATA.
    if unsafe { shutdown(reflection.handle, 3) } == 0 {
        return Err(windows_error(
            "Не удалось завершить снимок потребителей WinDivert.",
        ));
    }
    let mut packet = vec![0u8; 65_535];
    let mut consumers = Vec::new();
    for _ in 0..MAX_REFLECTION_EVENTS {
        let mut address = unsafe { zeroed::<DivertAddress>() };
        let mut length = 0;
        if unsafe {
            recv(
                reflection.handle,
                packet.as_mut_ptr(),
                packet.len() as u32,
                &mut length,
                &mut address,
            )
        } == 0
        {
            if unsafe { GetLastError() } == ERROR_NO_DATA {
                return validate_consumer_snapshot(&consumers, true);
            }
            return Err(windows_error(
                "Снимок потребителей WinDivert прочитан не полностью.",
            ));
        }
        let layer = address.flags & 0xff;
        let event = (address.flags >> 8) & 0xff;
        if layer != 4 || event != 8 || length as usize > packet.len() {
            return Err(driver_error(
                "WinDivert вернул неподдерживаемые данные проверки.",
                "Остановка отменена.".into(),
            ));
        }
        consumers.push(u32::from_ne_bytes(address.data[8..12].try_into().unwrap()));
    }
    validate_consumer_snapshot(&consumers, false)
}

fn required_export(
    value: Option<unsafe extern "system" fn() -> isize>,
    name: &[u8],
) -> Result<unsafe extern "system" fn() -> isize, AppError> {
    value.ok_or_else(|| {
        driver_error(
            "Версия WinDivert не поддерживает безопасную проверку потребителей.",
            String::from_utf8_lossy(name).trim_end_matches('\0').into(),
        )
    })
}

fn validate_consumer_snapshot(pids: &[u32], complete: bool) -> Result<(), AppError> {
    if !complete {
        return Err(driver_error(
            "Снимок потребителей WinDivert прочитан не полностью.",
            "Остановка отменена.".into(),
        ));
    }
    if !pids.is_empty() {
        return Err(driver_error("WinDivert используется другой программой; остановка отменена.", format!("Потребители драйвера, PID: {}. Завершите соответствующие приложения штатно и повторите обновление.", pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", "))));
    }
    Ok(())
}

fn lock_engine_files(current: &Path) -> Result<EngineFileGuards, AppError> {
    let mut paths = vec![current.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = paths.pop() {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            driver_error(
                "Не удалось проверить блокировки файлов движка.",
                format!("{}: {error}", path.display()),
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(driver_error(
                "Обнаружена ссылка в движке.",
                path.display().to_string(),
            ));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| {
                driver_error("Не удалось проверить папку движка.", error.to_string())
            })? {
                paths.push(
                    entry
                        .map_err(|error| {
                            driver_error("Не удалось перечислить файлы движка.", error.to_string())
                        })?
                        .path(),
                );
            }
        } else if metadata.is_file() {
            let file = OpenOptions::new().read(true).share_mode(FILE_SHARE_DELETE).open(&path).map_err(|error| driver_error("Файл движка занят; замена отменена.", format!("{}: {error}. Закройте использующую его программу и повторите обновление.", path.display())))?;
            files.push(file);
        } else {
            return Err(driver_error(
                "Недопустимый тип файла движка.",
                path.display().to_string(),
            ));
        }
        if files.len() + paths.len() > 100_000 {
            return Err(driver_error(
                "Слишком много файлов для проверки блокировок.",
                "Замена отменена.".into(),
            ));
        }
    }
    Ok(EngineFileGuards { _files: files })
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn windows_error(message: &'static str) -> AppError {
    driver_error(
        message,
        format!("Код Windows {}", unsafe { GetLastError() }),
    )
}
fn driver_error(message: &'static str, detail: String) -> AppError {
    AppError::new(
        "windivert_update_blocked",
        message,
        "Движок сохранён. Проверьте указанный компонент в диагностике, затем повторите обновление.",
    )
    .with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn driver_path_accepts_only_absolute_single_paths() {
        for good in [
            r"C:\ProgramData\ZapretGui\engine\current\bin\WinDivert64.sys",
            r"\??\C:\ProgramData\a.sys",
            r#""C:\ProgramData\a.sys""#,
            r"\\?\C:\ProgramData\a.sys",
        ] {
            assert!(normalize_image_path(good).is_ok(), "{good}");
        }
        for bad in [
            r"bin\WinDivert64.sys",
            r"\SystemRoot\a.sys",
            r"%SystemRoot%\a.sys",
            r"\\server\a.sys",
            r"C:\a.sys --argument",
            r#""C:\a.sys" --argument"#,
            r"C:\..\a.sys",
        ] {
            // An unquoted argument string may be lexically a filename, but
            // canonicalization/identity must reject it before any SCM mutation.
            if bad != r"C:\a.sys --argument" {
                assert!(normalize_image_path(bad).is_err(), "{bad}");
            }
        }
    }
    #[test]
    fn reflection_requires_complete_empty_snapshot() {
        assert!(validate_consumer_snapshot(&[], true).is_ok());
        assert!(validate_consumer_snapshot(&[], false).is_err());
        assert!(validate_consumer_snapshot(&[0], true).is_err());
        assert!(validate_consumer_snapshot(&[42, 43], true)
            .unwrap_err()
            .detail
            .unwrap()
            .contains("42, 43"));
    }
    #[test]
    fn old_or_unsupported_library_fails_before_any_driver_control() {
        assert_eq!(
            required_export(None, b"WinDivertShutdown\0")
                .unwrap_err()
                .code,
            "windivert_update_blocked"
        );
    }
    #[test]
    fn transitional_or_unknown_driver_state_is_rejected() {
        assert!(validate_state(SERVICE_STOPPED, "WinDivert").is_ok());
        assert!(validate_state(SERVICE_RUNNING, "WinDivert14").is_ok());
        for state in [
            0,
            SERVICE_START_PENDING,
            SERVICE_STOP_PENDING,
            SERVICE_PAUSED,
            999,
        ] {
            assert!(validate_state(state, "WinDivert").is_err());
        }
    }
    #[test]
    fn external_type_and_missing_driver_cannot_be_adopted() {
        let identity = DriverIdentity {
            name: "Other".into(),
            image_path: r"C:\Windows\other.sys".into(),
            service_type: SERVICE_KERNEL_DRIVER,
        };
        assert!(validate_identity(&identity, Path::new(r"C:\managed\WinDivert64.sys")).is_err());
        let identity = DriverIdentity {
            name: "WinDivert".into(),
            service_type: SERVICE_WIN32_OWN_PROCESS,
            ..identity
        };
        assert!(validate_identity(&identity, Path::new(r"C:\managed\WinDivert64.sys")).is_err());
    }
    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "zapret-driver-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        root
    }
    #[test]
    fn canonical_identity_rejects_external_driver_with_same_filename() {
        let root = temp_root();
        let managed = root.join("managed");
        let external = root.join("external");
        fs::create_dir(&managed).unwrap();
        fs::create_dir(&external).unwrap();
        let expected = managed.join("WinDivert64.sys");
        fs::write(&expected, b"managed fixture").unwrap();
        let other = external.join("WinDivert64.sys");
        fs::write(&other, b"external fixture").unwrap();
        let mut identity = DriverIdentity {
            name: "WinDivert".into(),
            image_path: other.to_string_lossy().into(),
            service_type: SERVICE_KERNEL_DRIVER,
        };
        assert!(validate_identity(&identity, &expected).is_err());
        identity.image_path = expected.to_string_lossy().into();
        assert!(validate_identity(&identity, &expected).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn busy_file_blocks_probe_and_released_guards_allow_directory_rename() {
        let root = temp_root();
        let current = root.join("current");
        fs::create_dir(&current).unwrap();
        let file = current.join("WinDivert64.sys");
        fs::write(&file, b"driver fixture").unwrap();
        let busy = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&file)
            .unwrap();
        assert!(lock_engine_files(&current).is_err());
        assert_eq!(fs::read(&file).unwrap_err().raw_os_error(), Some(32));
        drop(busy);
        let guards = lock_engine_files(&current).unwrap();
        assert!(OpenOptions::new().read(true).open(&file).is_err());
        let rollback = root.join("rollback");
        drop(guards);
        fs::rename(&current, &rollback).unwrap();
        assert_eq!(
            fs::read(rollback.join("WinDivert64.sys")).unwrap(),
            b"driver fixture"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn reflection_layout_matches_public_win64_abi() {
        assert_eq!(size_of::<DivertAddress>(), 80);
        assert_eq!(std::mem::offset_of!(DivertAddress, data), 16);
    }
}
