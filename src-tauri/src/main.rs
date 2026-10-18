#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    if !zapret_gui_lib::initialize_windows() {
        std::process::exit(1);
    }
    if std::env::args().nth(1).as_deref() == Some("--prepare-engine-storage") {
        if std::env::args().count() != 2 {
            std::process::exit(2);
        }
        std::process::exit(zapret_gui_lib::prepare_installed_storage());
    }
    if std::env::args().nth(1).as_deref() == Some("--ipc") {
        std::process::exit(zapret_gui_lib::run_service_helper());
    }
    if std::env::args().nth(1).as_deref() == Some("--manual-ipc") {
        std::process::exit(zapret_gui_lib::run_manual_helper());
    }
    if std::env::args().nth(1).as_deref() == Some("--scan-ipc") {
        std::process::exit(zapret_gui_lib::run_scan_helper());
    }
    zapret_gui_lib::run();
}
