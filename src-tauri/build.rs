fn main() {
    println!("cargo:rerun-if-changed=icons/icon.ico");
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "get_diagnostics",
            "get_config",
            "save_appearance",
            "import_appearance_asset",
            "read_appearance_asset",
            "get_strategies",
            "select_strategy",
            "start_manual",
            "stop_manual",
            "get_manual_status",
            "start_strategy_scan",
            "cancel_strategy_scan",
            "get_strategy_scan_state",
            "check_current_strategy",
            "recover_strategy_scan",
            "update_engine",
            "rollback_engine",
            "get_rollback_available",
            "open_service_console",
        ]),
    ))
    .expect("failed to prepare Tauri build");
}
