//! Open the official service menu in a visible, elevated Windows console.

use crate::error::AppError;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub(crate) fn open() -> Result<(), AppError> {
    crate::storage_security::verify_engine_storage()?;
    let root = crate::diagnostics::engine_dir().map_err(|detail| failure().with_detail(detail))?;
    crate::update::validate_staged_engine(&root, None)?;
    let root = fs::canonicalize(root).map_err(|error| failure().with_detail(error.to_string()))?;
    let batch = root.join("service.bat");
    let metadata =
        fs::symlink_metadata(&batch).map_err(|error| failure().with_detail(error.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err(
            failure().with_detail("service.bat должен быть обычным непустым файлом.".into())
        );
    }
    let batch =
        fs::canonicalize(batch).map_err(|error| failure().with_detail(error.to_string()))?;
    if batch.parent() != Some(root.as_path()) {
        return Err(failure().with_detail("service.bat находится вне папки движка.".into()));
    }
    let batch_arg = cmd_path(&batch)?;
    let root_arg = cmd_path(&root)?;
    if !cmd_safe(&batch_arg) || !cmd_safe(&root_arg) {
        return Err(failure().with_detail("Путь движка содержит символы командной строки.".into()));
    }

    let mut system_directory = [0u16; 32_768];
    let len = unsafe {
        GetSystemDirectoryW(system_directory.as_mut_ptr(), system_directory.len() as u32)
    } as usize;
    if len == 0 || len >= system_directory.len() {
        return Err(failure().with_detail(last_error()));
    }
    let cmd = PathBuf::from(OsString::from_wide(&system_directory[..len])).join("cmd.exe");
    let cmd_metadata =
        fs::symlink_metadata(&cmd).map_err(|error| failure().with_detail(error.to_string()))?;
    if !cmd_metadata.is_file() || cmd_metadata.file_type().is_symlink() {
        return Err(failure().with_detail("Системный cmd.exe недоступен.".into()));
    }

    // /S removes the outer quotation pair; /K leaves the official interactive
    // menu's console available to the user after the BAT returns.
    let arguments = format!("/D /S /K \"\"{batch_arg}\"\"");
    let verb = wide("runas");
    let file = wide_os(cmd.as_os_str());
    let parameters = wide(&arguments);
    let directory = wide(&root_arg);
    let mut info: SHELLEXECUTEINFOW = unsafe { zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.lpDirectory = directory.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_CANCELLED {
            return Err(AppError::new(
                "uac_cancelled",
                "Запрос прав администратора отменён.",
                "Чтобы открыть управление службой, повторите действие и подтвердите запрос Windows.",
            ));
        }
        return Err(failure().with_detail(format!("ShellExecuteExW: код Windows {code}")));
    }
    if !info.hProcess.is_null() {
        unsafe { CloseHandle(info.hProcess) };
    }
    Ok(())
}

fn cmd_path(path: &Path) -> Result<String, AppError> {
    let raw = path.to_str().ok_or_else(failure)?;
    let dos = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    let bytes = dos.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(failure().with_detail("Ожидался абсолютный локальный путь движка.".into()));
    }
    Ok(dos.to_owned())
}

fn cmd_safe(path: &str) -> bool {
    !path
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '%' | '!' | '^' | '&' | '|' | '<' | '>' | '"'))
}

fn failure() -> AppError {
    AppError::new(
        "service_console_failed",
        "Не удалось открыть официальный service.bat.",
        "Проверьте установку zapret и повторите попытку.",
    )
}

fn last_error() -> String {
    format!("Код Windows {}", unsafe { GetLastError() })
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cmd_metacharacters() {
        assert!(!cmd_safe(r"C:\ProgramData\ZapretGui%COMSPEC%\service.bat"));
        assert!(!cmd_safe(r"C:\ProgramData\ZapretGui&whoami\service.bat"));
        assert!(cmd_safe(
            r"C:\ProgramData\ZapretGui\engine\current\service.bat"
        ));
    }
}
