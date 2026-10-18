//! Fixed installer entry point; no frontend command or caller-supplied path.
use windows_sys::Win32::{
    System::LibraryLoader::{
        SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    },
    UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK},
};

fn show_error(message: &str) {
    let title: Vec<u16> = "ZAPRET — ошибка установки\0".encode_utf16().collect();
    let message: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

pub fn initialize_windows() -> bool {
    // Elevated helpers must not load DLLs from a caller-controlled working directory.
    if unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
    } == 0
    {
        show_error("Windows не смогла включить безопасную загрузку библиотек. Требуется Windows 10 или 11 x64.");
        return false;
    }
    true
}

pub fn prepare_installed_storage() -> i32 {
    let result = crate::service_helper::verify_installed_app()
        .and_then(|_| crate::storage_security::prepare_engine_storage());
    match result {
        Ok(_) => 0,
        Err(error) => {
            show_error(&format!(
                "{}\n{}\n{}",
                error.message,
                error.action,
                error.detail.unwrap_or_default()
            ));
            1
        }
    }
}
