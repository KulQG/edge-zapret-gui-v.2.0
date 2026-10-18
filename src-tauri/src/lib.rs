#[cfg(not(target_os = "windows"))]
compile_error!("ZAPRET GUI supports Windows only");
#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
compile_error!("ZAPRET GUI requires Windows x64");

mod appearance;
mod archive;
mod config;
mod diagnostics;
mod driver;
mod engine_update;
mod error;
mod installation;
mod logging;
mod manual_helper;
mod process;
mod scan_transport;
mod service_console;
mod service_helper;
mod storage_security;
mod strategy;
mod strategy_probe;
mod strategy_scan;
mod update;
mod upstream;

use config::{AppConfig, DataPaths};
use diagnostics::DiagnosticsSnapshot;
use error::AppError;
use process::{ProcessManager, ProcessStatus};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tauri::Emitter;

// Serialize read-modify-write operations so appearance saves cannot discard a
// strategy selection, or a migration overwrite a newer configuration.
static CONFIG_WRITE_LOCK: Mutex<()> = Mutex::new(());
static APPEARANCE_ASSET_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct ScanRuntime {
    inner: Mutex<ScanRuntimeInner>,
}

#[derive(Default)]
struct ScanRuntimeInner {
    active_id: Option<String>,
    cancel: Option<Arc<AtomicBool>>,
    progress: Option<strategy_scan::ScanProgress>,
}

impl ScanRuntime {
    fn begin(&self, operation_id: &str) -> Result<Arc<AtomicBool>, AppError> {
        let mut inner = self.inner.lock().map_err(|_| AppError::task_join())?;
        if inner.active_id.is_some() {
            return Err(scan_busy());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        inner.active_id = Some(operation_id.to_owned());
        inner.cancel = Some(Arc::clone(&cancel));
        inner.progress = None;
        Ok(cancel)
    }

    fn progress(&self, value: strategy_scan::ScanProgress) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.progress = Some(value);
        }
    }

    fn finish(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.active_id = None;
            inner.cancel = None;
        }
    }
}

fn scan_busy() -> AppError {
    AppError::new(
        "strategy_scan_busy",
        "Тест стратегий уже выполняется.",
        "Дождитесь завершения или остановите текущий тест.",
    )
}

fn operation_busy() -> AppError {
    AppError::new(
        "operation_busy",
        "Другое действие ещё выполняется.",
        "Дождитесь его завершения и повторите попытку.",
    )
}

fn scan_recovery_pending() -> AppError {
    AppError::new(
        "scan_recovery_pending",
        "Предыдущий тест требует восстановления стратегии.",
        "Откройте «Тесты ALT» и восстановите исходную стратегию.",
    )
}

fn validate_scan_operation_id(value: &str) -> Result<(), AppError> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(AppError::new(
            "scan_request_invalid",
            "Неверный идентификатор теста.",
            "Запустите тест повторно.",
        ))
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ManualSnapshot {
    status: ProcessStatus,
}

#[tauri::command]
async fn get_diagnostics() -> Result<DiagnosticsSnapshot, AppError> {
    tauri::async_runtime::spawn_blocking(|| {
        let mut snapshot =
            diagnostics::collect().map_err(|detail| AppError::diagnostics().with_detail(detail))?;
        match DataPaths::discover() {
            Ok(paths) => {
                let retention_days = match config::load_config(&paths) {
                    Ok(settings) => settings.log_retention_days,
                    Err(error) => {
                        snapshot.warnings.push(error.message.to_owned());
                        AppConfig::default().log_retention_days
                    }
                };
                if let Err(error) = logging::append_event(
                    &paths,
                    retention_days,
                    logging::LogLevel::Info,
                    logging::LogCode::DiagnosticsRead,
                ) {
                    snapshot.warnings.push(error.message.to_owned());
                }
            }
            Err(error) => snapshot.warnings.push(error.message.to_owned()),
        }
        Ok(snapshot)
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn get_config() -> Result<AppConfig, AppError> {
    tauri::async_runtime::spawn_blocking(|| {
        let _write = CONFIG_WRITE_LOCK
            .lock()
            .map_err(|_| AppError::config_write())?;
        let paths = DataPaths::discover()?;
        let settings = config::load_config(&paths)?;
        match std::fs::metadata(&paths.config_file) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                config::save_config(&paths, &settings)?;
            }
            Err(_) => return Err(AppError::config_read()),
        }
        Ok(settings)
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn get_strategies() -> Result<Vec<strategy::StrategySummary>, AppError> {
    tauri::async_runtime::spawn_blocking(|| {
        let root = diagnostics::engine_dir()
            .map_err(|detail| AppError::diagnostics().with_detail(detail))?;
        let discovered = strategy::discover_strategies(&root)?;
        Ok(discovered.into_iter().map(|item| item.summary).collect())
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn select_strategy(strategy_id: String) -> Result<(), AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let plan = resolve_strategy(&strategy_id)?;
        let _write = CONFIG_WRITE_LOCK
            .lock()
            .map_err(|_| AppError::config_write())?;
        let paths = DataPaths::discover()?;
        let mut config = config::load_config(&paths)?;
        config.selected_strategy = Some(plan.strategy_id);
        config::save_config(&paths, &config)
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn save_appearance(settings: config::AppearanceSettings) -> Result<AppConfig, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        settings.validate()?;
        let _write = CONFIG_WRITE_LOCK
            .lock()
            .map_err(|_| AppError::config_write())?;
        let _assets = APPEARANCE_ASSET_LOCK
            .lock()
            .map_err(|_| AppError::config_write())?;
        let paths = DataPaths::discover()?;
        appearance::verify_references(&paths, &settings)?;
        let mut current = config::load_config(&paths)?;
        current.appearance = settings;
        config::save_config(&paths, &current)?;
        // The configuration is durable before removing replaceable, unused copies.
        // Cleanup failure must not report an already successful save as a failure.
        let (level, code) = if appearance::prune_unused(&paths, &current.appearance).is_ok() {
            (logging::LogLevel::Info, logging::LogCode::ConfigSaved)
        } else {
            (
                logging::LogLevel::Warning,
                logging::LogCode::AppearanceCleanupFailed,
            )
        };
        let _ = logging::append_event(&paths, current.log_retention_days, level, code);
        Ok(current)
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn import_appearance_asset(
    request: tauri::ipc::Request<'_>,
) -> Result<appearance::ImportedAsset, AppError> {
    // Raw IPC avoids expanding image bytes into a large JSON number array.
    let bytes = match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes)
            if !bytes.is_empty() && bytes.len() <= 8 * 1024 * 1024 =>
        {
            bytes.clone()
        }
        _ => {
            return Err(AppError::new(
                "appearance_upload_invalid",
                "Не удалось принять изображение: файл пустой или больше 8 МиБ.",
                "Выберите PNG, JPEG или WebP размером до 8 МиБ.",
            ))
        }
    };
    let extension = request
        .headers()
        .get("x-image-extension")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "png" | "jpg" | "jpeg" | "webp"))
        .ok_or_else(|| {
            AppError::new(
                "appearance_extension_invalid",
                "Формат изображения не поддерживается.",
                "Выберите PNG, JPEG или WebP.",
            )
        })?
        .to_owned();
    tauri::async_runtime::spawn_blocking(move || {
        let _assets = APPEARANCE_ASSET_LOCK
            .lock()
            .map_err(|_| AppError::config_write())?;
        appearance::import_asset(&DataPaths::discover()?, &extension, &bytes)
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn read_appearance_asset(asset_id: String) -> Result<tauri::ipc::Response, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let _assets = APPEARANCE_ASSET_LOCK
            .lock()
            .map_err(|_| AppError::config_read())?;
        let bytes = appearance::read_asset(&DataPaths::discover()?, &asset_id)?;
        Ok(tauri::ipc::Response::new(bytes))
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn start_manual(
    strategy_id: String,
    manager: tauri::State<'_, Arc<Mutex<ProcessManager>>>,
    operation_gate: tauri::State<'_, Arc<Mutex<()>>>,
) -> Result<ManualSnapshot, AppError> {
    let manager = Arc::clone(manager.inner());
    let gate = Arc::clone(operation_gate.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = gate.try_lock().map_err(|_| operation_busy())?;
        if strategy_scan::pending_recovery()? {
            return Err(scan_recovery_pending());
        }
        let plan = resolve_strategy(&strategy_id)?;
        check_manual_conflicts(None)?;
        let status = manager
            .lock()
            .map_err(|_| manual_error("Не удалось получить управление процессом приложения."))?
            .start(plan)?;
        Ok(ManualSnapshot { status })
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn stop_manual(
    manager: tauri::State<'_, Arc<Mutex<ProcessManager>>>,
    operation_gate: tauri::State<'_, Arc<Mutex<()>>>,
) -> Result<ManualSnapshot, AppError> {
    let manager = Arc::clone(manager.inner());
    let gate = Arc::clone(operation_gate.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = gate.try_lock().map_err(|_| operation_busy())?;
        if strategy_scan::pending_recovery()? {
            return Err(scan_recovery_pending());
        }
        let status = manager
            .lock()
            .map_err(|_| manual_error("Не удалось получить управление процессом приложения."))?
            .stop()?;
        Ok(ManualSnapshot { status })
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn update_engine(
    operation_id: String,
    app: tauri::AppHandle,
    operation_gate: tauri::State<'_, Arc<Mutex<()>>>,
) -> Result<engine_update::EngineUpdateResult, AppError> {
    run_engine_operation(
        "update",
        operation_id,
        app,
        Arc::clone(operation_gate.inner()),
    )
    .await
}

#[tauri::command]
async fn rollback_engine(
    operation_id: String,
    app: tauri::AppHandle,
    operation_gate: tauri::State<'_, Arc<Mutex<()>>>,
) -> Result<engine_update::EngineUpdateResult, AppError> {
    run_engine_operation(
        "rollback",
        operation_id,
        app,
        Arc::clone(operation_gate.inner()),
    )
    .await
}

#[tauri::command]
async fn get_rollback_available() -> Result<bool, AppError> {
    tauri::async_runtime::spawn_blocking(|| {
        let current = diagnostics::engine_dir()
            .map_err(|detail| AppError::diagnostics().with_detail(detail))?;
        if !current.exists() {
            return Ok(false);
        }
        update::retained_engine_rollback(&current).map(|path| path.is_some())
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn open_service_console(
    operation_gate: tauri::State<'_, Arc<Mutex<()>>>,
) -> Result<(), AppError> {
    let gate = Arc::clone(operation_gate.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = gate.try_lock().map_err(|_| operation_busy())?;
        if strategy_scan::pending_recovery()? {
            return Err(AppError::new(
                "scan_recovery_pending",
                "Предыдущий тест требует восстановления стратегии.",
                "Восстановите стратегию перед открытием консоли.",
            ));
        }
        service_console::open()
    })
    .await
    .map_err(|_| AppError::task_join())?
}

async fn run_engine_operation(
    kind: &'static str,
    operation_id: String,
    app: tauri::AppHandle,
    gate: Arc<Mutex<()>>,
) -> Result<engine_update::EngineUpdateResult, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = gate.try_lock().map_err(|_| operation_busy())?;
        if strategy_scan::pending_recovery()? {
            return Err(AppError::new(
                "scan_recovery_pending",
                "Предыдущий тест требует восстановления стратегии.",
                "Восстановите стратегию перед обновлением.",
            ));
        }
        let selected_strategy = if kind == "update" {
            config::load_config(&DataPaths::discover()?)?
                .selected_strategy
                .map(|id| engine_update::SelectedStrategy { id })
        } else {
            None
        };
        service_helper::invoke_elevated_update(kind, &operation_id, selected_strategy, |progress| {
            let is_download_tick = matches!(progress.stage, engine_update::UpdateStage::Download)
                && matches!(progress.state, engine_update::UpdateProgressState::Started)
                && progress.message.starts_with("Загружено ");
            if !is_download_tick {
                if let Ok(paths) = DataPaths::discover() {
                    let retention = config::load_config(&paths)
                        .map(|value| value.log_retention_days)
                        .unwrap_or_else(|_| AppConfig::default().log_retention_days);
                    let _ = logging::append_update_progress(&paths, retention, &progress);
                }
            }
            let _ = app.emit("engine-update-progress", progress);
        })
    })
    .await
    .map_err(|_| AppError::task_join())?
}

pub fn run_service_helper() -> i32 {
    service_helper::run_helper()
}

pub fn run_manual_helper() -> i32 {
    manual_helper::run_helper()
}

pub fn run_scan_helper() -> i32 {
    scan_transport::run_helper()
}

pub fn initialize_windows() -> bool {
    installation::initialize_windows()
}

pub fn prepare_installed_storage() -> i32 {
    installation::prepare_installed_storage()
}

#[tauri::command]
async fn get_manual_status(
    manager: tauri::State<'_, Arc<Mutex<ProcessManager>>>,
) -> Result<ManualSnapshot, AppError> {
    let manager = Arc::clone(manager.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let mut state = manager
            .lock()
            .map_err(|_| manual_error("Не удалось получить состояние процесса приложения."))?;
        let status = state.status();
        Ok(ManualSnapshot { status })
    })
    .await
    .map_err(|_| AppError::task_join())?
}

#[tauri::command]
async fn start_strategy_scan(
    operation_id: String,
    strategy_ids: Vec<String>,
    scope: strategy_scan::ScanScope,
    fast_mode: bool,
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<ScanRuntime>>,
    operation_gate: tauri::State<'_, Arc<Mutex<()>>>,
) -> Result<strategy_scan::ScanProgress, AppError> {
    validate_scan_operation_id(&operation_id)?;
    if strategy_ids.is_empty() || strategy_ids.len() > 64 {
        return Err(AppError::new(
            "scan_request_invalid",
            "Выберите от одной до 64 стратегий ALT.",
            "Исправьте выбор и запустите тест повторно.",
        ));
    }
    let runtime = Arc::clone(runtime.inner());
    let gate = Arc::clone(operation_gate.inner());
    let cancelled = runtime.begin(&operation_id)?;
    let request = strategy_scan::ScanRequest {
        operation_id,
        strategy_ids,
        scope,
        fast_mode,
    };
    let runtime_for_work = Arc::clone(&runtime);
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _operation = gate.try_lock().map_err(|_| operation_busy())?;
        if strategy_scan::pending_recovery()? {
            return Err(AppError::new(
                "scan_recovery_pending",
                "Предыдущий тест требует восстановления стратегии.",
                "Восстановите стратегию перед новым тестом.",
            ));
        }
        scan_transport::invoke_scan(request, cancelled, |progress| {
            runtime_for_work.progress(progress.clone());
            let _ = app.emit("strategy-scan-progress", progress);
        })
    })
    .await
    .map_err(|_| AppError::task_join());
    runtime.finish();
    result?
}

#[tauri::command]
async fn cancel_strategy_scan(
    operation_id: String,
    runtime: tauri::State<'_, Arc<ScanRuntime>>,
) -> Result<(), AppError> {
    use std::sync::atomic::Ordering;
    let inner = runtime.inner.lock().map_err(|_| AppError::task_join())?;
    if inner.active_id.as_deref() != Some(operation_id.as_str()) {
        return Err(AppError::new(
            "scan_not_active",
            "Этот тест уже завершён.",
            "Обновите состояние теста.",
        ));
    }
    if let Some(cancel) = &inner.cancel {
        cancel.store(true, Ordering::SeqCst);
    }
    Ok(())
}

#[tauri::command]
async fn get_strategy_scan_state(
    runtime: tauri::State<'_, Arc<ScanRuntime>>,
) -> Result<strategy_scan::ScanState, AppError> {
    let (active, progress) = {
        let inner = runtime.inner.lock().map_err(|_| AppError::task_join())?;
        (inner.active_id.is_some(), inner.progress.clone())
    };
    let recovery_pending = tauri::async_runtime::spawn_blocking(strategy_scan::pending_recovery)
        .await
        .map_err(|_| AppError::task_join())??;
    Ok(strategy_scan::ScanState {
        active,
        progress,
        recovery_pending,
    })
}

#[tauri::command]
async fn check_current_strategy(
    operation_id: String,
    scope: strategy_scan::ScanScope,
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<ScanRuntime>>,
    operation_gate: tauri::State<'_, Arc<Mutex<()>>>,
) -> Result<strategy_scan::ScanResult, AppError> {
    use std::sync::atomic::Ordering;
    validate_scan_operation_id(&operation_id)?;
    let runtime = Arc::clone(runtime.inner());
    let gate = Arc::clone(operation_gate.inner());
    let cancelled = runtime.begin(&operation_id)?;
    let runtime_for_work = Arc::clone(&runtime);
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _operation = gate.try_lock().map_err(|_| operation_busy())?;
        if strategy_scan::pending_recovery()? {
            return Err(AppError::new(
                "scan_recovery_pending",
                "Предыдущий тест требует восстановления стратегии.",
                "Восстановите стратегию перед проверкой.",
            ));
        }
        strategy_scan::check_current(
            operation_id,
            scope,
            || cancelled.load(Ordering::SeqCst),
            |progress| {
                runtime_for_work.progress(progress.clone());
                let _ = app.emit("strategy-scan-progress", progress);
            },
        )
    })
    .await
    .map_err(|_| AppError::task_join());
    runtime.finish();
    result?
}

#[tauri::command]
async fn recover_strategy_scan(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<ScanRuntime>>,
    operation_gate: tauri::State<'_, Arc<Mutex<()>>>,
) -> Result<(), AppError> {
    let runtime = Arc::clone(runtime.inner());
    let gate = Arc::clone(operation_gate.inner());
    runtime.begin("recovery")?;
    let runtime_for_work = Arc::clone(&runtime);
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _operation = gate.try_lock().map_err(|_| operation_busy())?;
        scan_transport::invoke_recovery(|progress| {
            runtime_for_work.progress(progress.clone());
            let _ = app.emit("strategy-scan-progress", progress);
        })
    })
    .await
    .map_err(|_| AppError::task_join());
    runtime.finish();
    result?
}

fn resolve_strategy(strategy_id: &str) -> Result<strategy::LaunchPlan, AppError> {
    storage_security::verify_engine_storage()?;
    let root =
        diagnostics::engine_dir().map_err(|detail| AppError::diagnostics().with_detail(detail))?;
    let strategies = strategy::discover_strategies(&root)?;
    strategies
        .into_iter()
        .find(|strategy| strategy.summary.id == strategy_id)
        .and_then(|strategy| strategy.launch_plan)
        .ok_or_else(|| {
            AppError::new(
                "strategy_unavailable",
                "Выбранная стратегия отсутствует или не поддерживается.",
                "Обновите список стратегий и выберите вариант, отмеченный как поддерживаемый.",
            )
            .with_detail(strategy_id.to_owned())
        })
}

fn check_manual_conflicts(owned_pid: Option<u32>) -> Result<(), AppError> {
    let diagnostics =
        diagnostics::collect().map_err(|detail| AppError::diagnostics().with_detail(detail))?;
    if !diagnostics.engine.ready {
        return Err(manual_error(
            diagnostics
                .engine
                .issue
                .as_deref()
                .unwrap_or("Движок zapret не установлен."),
        ));
    }
    if !matches!(diagnostics.service.state.as_str(), "missing" | "stopped") {
        return Err(manual_error(&format!(
            "Состояние службы zapret — «{}». Временный режим не будет запущен, пока конфликт не устранён.",
            diagnostics.service.state
        )));
    }
    if let Some(process) = diagnostics
        .processes
        .iter()
        .find(|process| Some(process.pid) != owned_pid)
    {
        return Err(manual_error(&format!(
            "Обнаружен winws.exe PID {} ({}). Приложение не будет останавливать этот процесс автоматически.",
            process.pid,
            process.executable_path.as_deref().unwrap_or("путь недоступен")
        )));
    }
    if diagnostics.warnings.iter().any(|warning| {
        warning.contains("перечислить процессы") || warning.contains("прочитан не полностью")
    }) {
        return Err(manual_error(
            "Список процессов прочитан не полностью, поэтому отсутствие конфликтов не подтверждено.",
        ));
    }
    if diagnostics.win_divert.state == "running" && !diagnostics.win_divert.managed {
        return Err(manual_error(
            "Активный WinDivert не подтверждён как принадлежащий движку. Проверьте его путь в диагностике.",
        ));
    }
    if !matches!(
        diagnostics.win_divert.state.as_str(),
        "missing" | "stopped" | "running"
    ) || diagnostics.win_divert.error.is_some()
    {
        return Err(manual_error(
            "Не удалось надёжно определить состояние WinDivert. Проверьте раздел «Диагностика».",
        ));
    }
    Ok(())
}

fn manual_error(detail: &str) -> AppError {
    AppError::new(
        "manual_process_conflict",
        "Не удалось безопасно запустить временную стратегию.",
        "Устраните указанную причину и повторите попытку.",
    )
    .with_detail(detail.to_owned())
}

pub fn run() {
    tauri::Builder::default()
        .manage(Arc::new(Mutex::new(ProcessManager::default())))
        .manage(Arc::new(Mutex::new(())))
        .manage(Arc::new(ScanRuntime::default()))
        .invoke_handler(tauri::generate_handler![
            get_diagnostics,
            get_config,
            save_appearance,
            import_appearance_asset,
            read_appearance_asset,
            get_strategies,
            select_strategy,
            start_manual,
            stop_manual,
            get_manual_status,
            start_strategy_scan,
            cancel_strategy_scan,
            get_strategy_scan_state,
            check_current_strategy,
            recover_strategy_scan,
            update_engine,
            rollback_engine,
            get_rollback_available,
            open_service_console
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Tauri application");
}
