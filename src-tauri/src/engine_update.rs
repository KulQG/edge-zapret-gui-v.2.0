//! Download, stage, and replace official Flowseal releases. Runtime changes go
//! through the same verified BAT runner as the Start and Stop buttons.

use crate::archive;
use crate::diagnostics::{self, DiagnosticsSnapshot};
use crate::error::AppError;
use crate::manual_helper;
use crate::process::ProcessState;
use crate::{update, upstream};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EngineUpdateProgress {
    pub operation_id: String,
    pub sequence: u64,
    pub stage: UpdateStage,
    pub state: UpdateProgressState,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum UpdateStage {
    Download,
    Validate,
    StopService,
    StopManual,
    StopWinDivert,
    Replace,
    Restore,
    Complete,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UpdateProgressState {
    Started,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EngineUpdateResult {
    pub release: String,
    pub restored_mode: RestoredMode,
    pub cleanup_warning: Option<AppError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RestoredMode {
    Manual,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelectedStrategy {
    pub id: String,
}

#[derive(Debug, Clone)]
struct RuntimeSnapshot {
    pid: u32,
    created_at_ms: u64,
    strategy_id: String,
}

/// The selected strategy is a filename ID, never a path or command. The caller
/// runs this in the elevated update helper and reports progress over IPC.
pub(crate) fn execute<F>(
    operation_id: &str,
    selected_strategy: Option<SelectedStrategy>,
    mut report: F,
) -> Result<EngineUpdateResult, AppError>
where
    F: FnMut(EngineUpdateProgress),
{
    validate_operation_id(operation_id)?;
    let (parent, current) = engine_paths()?;
    let _lock = acquire_update_lock(&parent)?;
    if crate::strategy_scan::pending_recovery()? {
        return Err(failure(
            "Тест стратегий ещё выполняется или требует восстановления.",
            "Завершите тест и восстановите прежнюю стратегию перед обновлением.".into(),
        ));
    }
    let before = capture_runtime(!plain_directory_exists(&current)?)?;
    if update::initial_install_recovery_pending(&current)? {
        require_idle(&before)?;
    }
    // Recovery of an interrupted rename may move `current`. A retained
    // completed update is read-only here; other journal phases require an
    // idle runtime before recovery is allowed to touch directories.
    if before.is_some()
        && fs::symlink_metadata(parent.join(".zapret-update-transaction.json")).is_ok()
        && update::retained_engine_rollback(&current)?.is_none()
    {
        return Err(failure(
            "Незавершённое обновление требует остановленного движка для восстановления.",
            "Работающая стратегия не изменена. Остановите её в приложении и повторите обновление."
                .into(),
        ));
    }
    let _ = update::recover_engine_update(&current)?;
    let first_install = !plain_directory_exists(&current)?;
    if !first_install {
        update::validate_staged_engine(&current, None)?;
    }
    let before = capture_runtime(first_install)?;
    let zip = parent.join(format!(".zapret-{operation_id}.zip"));
    let stage = parent.join(format!(".stage-{operation_id}"));
    let rollback = parent.join(format!(".rollback-{operation_id}"));
    for path in [&zip, &stage, &rollback] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(failure(
                "Папка обновления уже используется.",
                path.display().to_string(),
            ));
        }
    }

    let mut sequence = 0;
    emit(
        &mut report,
        operation_id,
        &mut sequence,
        UpdateStage::Download,
        UpdateProgressState::Started,
        "Скачивание официального релиза Flowseal",
        None,
    );
    let release = match upstream::download_latest_release(&zip, &parent, |downloaded, total| {
        emit(
            &mut report,
            operation_id,
            &mut sequence,
            UpdateStage::Download,
            UpdateProgressState::Started,
            &format!("Загружено {downloaded} из {total} байт"),
            None,
        );
    }) {
        Ok(release) => release,
        Err(error) => {
            let _ = fs::remove_file(&zip);
            emit_error(
                &mut report,
                operation_id,
                &mut sequence,
                UpdateStage::Download,
                &error,
            );
            return Err(error);
        }
    };
    emit(
        &mut report,
        operation_id,
        &mut sequence,
        UpdateStage::Download,
        UpdateProgressState::Completed,
        "Официальный архив загружен и проверен по SHA-256",
        None,
    );

    emit(
        &mut report,
        operation_id,
        &mut sequence,
        UpdateStage::Validate,
        UpdateProgressState::Started,
        "Проверка подготовленного релиза",
        None,
    );
    let prepared = (|| {
        archive::extract_flowseal_zip(&release.path, &stage, &release.tag).map_err(|error| {
            failure(
                "Не удалось безопасно распаковать официальный архив.",
                error.to_string(),
            )
        })?;
        if !first_install {
            preserve_engine_customization(&current, &stage)?;
        }
        update::validate_staged_engine(
            &stage,
            before.as_ref().map(|value| value.strategy_id.as_str()),
        )?;
        // A saved selection must remain usable after replacement. On a first
        // installation a stale selection cannot prevent installing the engine.
        if let Some(selected) = selected_strategy.as_ref().filter(|_| !first_install) {
            update::validate_staged_engine(&stage, Some(&selected.id))?;
        }
        crate::storage_security::verify_engine_storage()?;
        // The older retained copy can be released only after this release is
        // staged and checked, and before any current runtime is stopped.
        if !first_install && update::retained_engine_rollback(&current)?.is_some() {
            update::release_retained_engine_update(&current)?;
        }
        Ok::<(), AppError>(())
    })();
    if let Err(error) = prepared {
        let _ = fs::remove_file(&zip);
        let _ = fs::remove_dir_all(&stage);
        emit_error(
            &mut report,
            operation_id,
            &mut sequence,
            UpdateStage::Validate,
            &error,
        );
        return Err(error);
    }
    emit(
        &mut report,
        operation_id,
        &mut sequence,
        UpdateStage::Validate,
        UpdateProgressState::Completed,
        &format!("Релиз {} проверен", release.tag),
        None,
    );

    let result = if first_install {
        install_first(
            &current,
            &stage,
            &release.tag,
            operation_id,
            &mut sequence,
            &mut report,
        )
    } else {
        replace_current(
            &current,
            &stage,
            &rollback,
            &release.tag,
            before.as_ref(),
            operation_id,
            &mut sequence,
            &mut report,
        )
    };
    let _ = fs::remove_file(&zip);
    // The stage may hold the promoted release after a rollback. The journal
    // owns cleanup from this point; do not delete it on a broad error path.
    result
}

/// User-requested rollback to the retained known-working release. The caller
/// obtains user approval after connectivity testing; this function never infers
/// that a running process proves bypass success.
pub(crate) fn rollback_retained<F>(
    operation_id: &str,
    mut report: F,
) -> Result<EngineUpdateResult, AppError>
where
    F: FnMut(EngineUpdateProgress),
{
    validate_operation_id(operation_id)?;
    let (parent, current) = engine_paths()?;
    let _lock = acquire_update_lock(&parent)?;
    if crate::strategy_scan::pending_recovery()? {
        return Err(failure(
            "Тест стратегий ещё выполняется или требует восстановления.",
            "Завершите тест и восстановите прежнюю стратегию перед откатом.".into(),
        ));
    }
    let rollback = update::retained_engine_rollback(&current)?.ok_or_else(|| {
        failure(
            "Предыдущая версия не сохранена для отката.",
            "Резервная копия отсутствует или уже очищается.".into(),
        )
    })?;
    update::validate_staged_engine(&rollback, None)?;
    let before = capture_runtime(false)?;
    preserve_engine_customization(&current, &rollback)?;
    if let Some(runtime) = before.as_ref() {
        update::validate_staged_engine(&rollback, Some(&runtime.strategy_id))?;
    }
    let mut sequence = 0;
    emit(
        &mut report,
        operation_id,
        &mut sequence,
        UpdateStage::Validate,
        UpdateProgressState::Completed,
        "Сохранённая версия проверена",
        None,
    );
    let mut stopped = false;
    let mut swap_attempted = false;
    let mut started: Option<RuntimeSnapshot> = None;
    let result: Result<EngineUpdateResult, AppError> = (|| {
        if let Some(runtime) = before.as_ref() {
            stop_owned(runtime)?;
            stopped = true;
        }
        ensure_files_idle(&current)?;
        emit(
            &mut report,
            operation_id,
            &mut sequence,
            UpdateStage::Replace,
            UpdateProgressState::Started,
            "Возврат сохранённой версии",
            None,
        );
        swap_attempted = true;
        update::rollback_retained_engine(&current)?;
        update::validate_staged_engine(&current, None)?;
        if let Some(runtime) = before.as_ref() {
            started = Some(start_owned(&runtime.strategy_id)?);
        }
        // Only a cleanup failure AFTER the durable commit is a warning.
        // Pre-commit errors still permit undo to the release used before the
        // user requested rollback.
        let cleanup_warning = match update::finalize_retained_rollback(&current) {
            Ok(()) => None,
            Err(error) if update::user_rollback_committed(&current)? => {
                Some(cleanup_warning(error))
            }
            Err(error) => return Err(error),
        };
        Ok(EngineUpdateResult {
            release: release_label(&current),
            restored_mode: mode(before.as_ref()),
            cleanup_warning,
        })
    })();
    match result {
        Ok(value) => {
            emit(
                &mut report,
                operation_id,
                &mut sequence,
                UpdateStage::Complete,
                UpdateProgressState::Completed,
                "Откат завершён",
                None,
            );
            Ok(value)
        }
        Err(error) => {
            let recovery = if swap_attempted {
                match update::retained_engine_rollback(&current) {
                    Ok(Some(_)) => restore_runtime(before.as_ref()),
                    Ok(None) => update::resume_retained_rollback(&current)
                        .and_then(|()| stop_started(started.as_ref()))
                        .and_then(|()| ensure_files_idle(&current))
                        .and_then(|()| update::undo_retained_rollback(&current))
                        .and_then(|()| restore_runtime(before.as_ref())),
                    Err(recovery) => Err(recovery),
                }
            } else if stopped {
                restore_runtime(before.as_ref())
            } else {
                Ok(())
            };
            let error = combine_recovery(error, recovery);
            emit_error(
                &mut report,
                operation_id,
                &mut sequence,
                UpdateStage::Restore,
                &error,
            );
            Err(error)
        }
    }
}

fn install_first<F: FnMut(EngineUpdateProgress)>(
    current: &Path,
    stage: &Path,
    release: &str,
    id: &str,
    sequence: &mut u64,
    report: &mut F,
) -> Result<EngineUpdateResult, AppError> {
    let result: Result<EngineUpdateResult, AppError> = (|| {
        require_idle(&capture_runtime(true)?)?;
        crate::storage_security::verify_engine_storage()?;
        emit(
            report,
            id,
            sequence,
            UpdateStage::Replace,
            UpdateProgressState::Started,
            "Установка проверенного движка",
            None,
        );
        update::promote_initial_engine(stage, current)?;
        update::validate_staged_engine(current, None)?;
        crate::storage_security::verify_engine_storage()?;
        update::finalize_initial_engine(current)?;
        Ok(EngineUpdateResult {
            release: release.to_owned(),
            restored_mode: RestoredMode::Stopped,
            cleanup_warning: None,
        })
    })();
    if let Err(error) = &result {
        let recovery = if update::initial_install_recovery_pending(current)? {
            require_idle(&capture_runtime(true)?)
                .and_then(|()| update::recover_engine_update(current).map(|_| ()))
        } else {
            Ok(())
        };
        let error = combine_recovery(error.clone(), recovery);
        emit_error(report, id, sequence, UpdateStage::Replace, &error);
        return Err(error);
    }
    emit(
        report,
        id,
        sequence,
        UpdateStage::Complete,
        UpdateProgressState::Completed,
        "Движок установлен; запущенного режима до установки не было",
        None,
    );
    result
}

#[allow(clippy::too_many_arguments)]
fn replace_current<F: FnMut(EngineUpdateProgress)>(
    current: &Path,
    stage: &Path,
    rollback: &Path,
    release: &str,
    before: Option<&RuntimeSnapshot>,
    id: &str,
    sequence: &mut u64,
    report: &mut F,
) -> Result<EngineUpdateResult, AppError> {
    let mut stopped = false;
    let mut promoted = false;
    let mut started: Option<RuntimeSnapshot> = None;
    let result = (|| {
        if let Some(runtime) = before {
            emit(
                report,
                id,
                sequence,
                UpdateStage::StopManual,
                UpdateProgressState::Started,
                "Остановка запущенной стратегии",
                Some(format!("PID {}", runtime.pid)),
            );
            stop_owned(runtime)?;
            stopped = true;
            emit(
                report,
                id,
                sequence,
                UpdateStage::StopManual,
                UpdateProgressState::Completed,
                "Запущенная стратегия остановлена",
                None,
            );
        }
        emit(
            report,
            id,
            sequence,
            UpdateStage::StopWinDivert,
            UpdateProgressState::Started,
            "Проверка WinDivert и блокировки файлов",
            None,
        );
        ensure_files_idle(current)?;
        emit(
            report,
            id,
            sequence,
            UpdateStage::StopWinDivert,
            UpdateProgressState::Completed,
            "Файлы движка доступны для замены",
            None,
        );
        emit(
            report,
            id,
            sequence,
            UpdateStage::Replace,
            UpdateProgressState::Started,
            "Установка новой версии с сохранением предыдущей",
            None,
        );
        update::promote_engine(stage, current, rollback)?;
        promoted = true;
        update::validate_staged_engine(
            current,
            before.map(|runtime| runtime.strategy_id.as_str()),
        )?;
        emit(
            report,
            id,
            sequence,
            UpdateStage::Replace,
            UpdateProgressState::Completed,
            "Новая версия установлена",
            None,
        );
        if let Some(runtime) = before {
            emit(
                report,
                id,
                sequence,
                UpdateStage::Restore,
                UpdateProgressState::Started,
                "Запуск прежней стратегии официальным BAT",
                None,
            );
            started = Some(start_owned(&runtime.strategy_id)?);
        }
        emit(
            report,
            id,
            sequence,
            UpdateStage::Restore,
            UpdateProgressState::Completed,
            "Прежний режим восстановлен",
            None,
        );
        update::commit_engine_update_retaining_rollback(current, rollback)?;
        Ok(EngineUpdateResult {
            release: release.to_owned(),
            restored_mode: mode(before),
            cleanup_warning: None,
        })
    })();
    match result {
        Ok(value) => {
            emit(
                report,
                id,
                sequence,
                UpdateStage::Complete,
                UpdateProgressState::Completed,
                "Готово; предыдущая версия сохранена для отката",
                None,
            );
            Ok(value)
        }
        Err(error) => {
            let recovery = if promoted {
                stop_started(started.as_ref())
                    .and_then(|()| ensure_files_idle(current))
                    .and_then(|()| update::rollback_engine(current, rollback))
                    .and_then(|()| restore_runtime(before))
                    .and_then(|()| update::recover_engine_update(current).map(|_| ()))
            } else if stopped {
                update::recover_engine_update(current)
                    .map(|_| ())
                    .and_then(|()| restore_runtime(before))
            } else {
                Ok(())
            };
            let error = combine_recovery(error, recovery);
            emit_error(report, id, sequence, UpdateStage::Restore, &error);
            Err(error)
        }
    }
}

fn engine_paths() -> Result<(PathBuf, PathBuf), AppError> {
    let current = diagnostics::engine_dir()
        .map_err(|detail| failure("Не удалось определить папку движка.", detail))?;
    let parent = current
        .parent()
        .ok_or_else(|| failure("Путь движка неверен.", current.display().to_string()))?
        .canonicalize()
        .map_err(|error| failure("Не удалось проверить папку обновления.", error.to_string()))?;
    Ok((parent.clone(), parent.join("current")))
}

fn capture_runtime(first_install: bool) -> Result<Option<RuntimeSnapshot>, AppError> {
    let snapshot = diagnostics::collect()
        .map_err(|detail| failure("Не удалось проверить состояние движка.", detail))?;
    if snapshot.service.installed || snapshot.service.state != "missing" {
        return Err(failure(
            "Обновление при установленной службе zapret пока недоступно.",
            "Проверьте службу через официальный service.bat; приложение не изменяло её состояние."
                .into(),
        ));
    }
    let status = manual_helper::status();
    if matches!(status.state, ProcessState::Error) {
        return Err(status.error.unwrap_or_else(|| {
            failure(
                "Не удалось проверить управляемый процесс.",
                "Запуск или остановка не выполнялись.".into(),
            )
        }));
    }
    let runtime = if status.running {
        Some(RuntimeSnapshot {
            pid: status
                .pid
                .ok_or_else(|| failure("Неизвестен PID управляемого процесса.", "".into()))?,
            created_at_ms: status.created_at_ms.ok_or_else(|| {
                failure(
                    "Неизвестно время создания управляемого процесса.",
                    "".into(),
                )
            })?,
            strategy_id: status
                .strategy_id
                .ok_or_else(|| failure("Неизвестна стратегия управляемого процесса.", "".into()))?,
        })
    } else {
        None
    };
    validate_processes(&snapshot, runtime.as_ref())?;
    if first_install {
        require_idle(&runtime)?;
        if !matches!(snapshot.win_divert.state.as_str(), "missing" | "stopped") {
            return Err(failure(
                "WinDivert активен или его состояние не определено.",
                "Первая установка не изменяет работающий драйвер.".into(),
            ));
        }
    }
    Ok(runtime)
}

fn validate_processes(
    snapshot: &DiagnosticsSnapshot,
    owned: Option<&RuntimeSnapshot>,
) -> Result<(), AppError> {
    if snapshot.warnings.iter().any(|warning| {
        warning.contains("процесс")
            && (warning.contains("полностью") || warning.contains("перечислить"))
    }) {
        return Err(failure(
            "Список процессов прочитан не полностью.",
            "Обновление остановлено.".into(),
        ));
    }
    for process in &snapshot.processes {
        if process.error.is_some()
            || !process.managed
            || owned.map(|value| value.pid) != Some(process.pid)
        {
            return Err(failure(
                "Обнаружен процесс winws.exe, которым приложение не владеет.",
                format!(
                    "PID {}. Приложение не завершает неизвестные процессы.",
                    process.pid
                ),
            ));
        }
    }
    if owned.is_some()
        && !snapshot
            .processes
            .iter()
            .any(|value| Some(value.pid) == owned.map(|value| value.pid))
    {
        return Err(failure(
            "Управляемый winws.exe не найден в проверке процессов.",
            "Обновление остановлено.".into(),
        ));
    }
    Ok(())
}

fn require_idle(runtime: &Option<RuntimeSnapshot>) -> Result<(), AppError> {
    if runtime.is_some() {
        Err(failure(
            "Первая установка требует остановленного движка.",
            "Работающий процесс не изменён.".into(),
        ))
    } else {
        Ok(())
    }
}

fn stop_owned(runtime: &RuntimeSnapshot) -> Result<(), AppError> {
    let status = manual_helper::status();
    if !status.running
        || status.pid != Some(runtime.pid)
        || status.created_at_ms != Some(runtime.created_at_ms)
        || status.strategy_id.as_deref() != Some(runtime.strategy_id.as_str())
    {
        return Err(failure(
            "Работающая стратегия изменилась во время обновления.",
            "Процесс не остановлен.".into(),
        ));
    }
    manual_helper::stop()?;
    Ok(())
}

fn stop_started(started: Option<&RuntimeSnapshot>) -> Result<(), AppError> {
    let status = manual_helper::status();
    if status.running {
        let started = started.ok_or_else(|| {
            failure(
                "После ошибки запущен неподтверждённый процесс.",
                "Автоматическая остановка запрещена; проверьте процесс вручную.".into(),
            )
        })?;
        stop_owned(started)?;
    }
    Ok(())
}

fn start_owned(strategy_id: &str) -> Result<RuntimeSnapshot, AppError> {
    let status = manual_helper::start(strategy_id)?;
    if !status.running || status.strategy_id.as_deref() != Some(strategy_id) {
        return Err(failure(
            "Запуск стратегии не подтверждён.",
            strategy_id.to_owned(),
        ));
    }
    Ok(RuntimeSnapshot {
        pid: status
            .pid
            .ok_or_else(|| failure("Неизвестен PID новой стратегии.", strategy_id.to_owned()))?,
        created_at_ms: status.created_at_ms.ok_or_else(|| {
            failure(
                "Неизвестно время создания новой стратегии.",
                strategy_id.to_owned(),
            )
        })?,
        strategy_id: strategy_id.to_owned(),
    })
}

fn restore_runtime(before: Option<&RuntimeSnapshot>) -> Result<(), AppError> {
    if let Some(runtime) = before {
        start_owned(&runtime.strategy_id).map(|_| ())
    } else {
        Ok(())
    }
}

fn ensure_files_idle(current: &Path) -> Result<(), AppError> {
    let snapshot = capture_runtime(false)?;
    require_idle(&snapshot)?;
    let diagnostics = diagnostics::collect()
        .map_err(|detail| failure("Не удалось проверить WinDivert.", detail))?;
    if matches!(diagnostics.win_divert.state.as_str(), "unknown" | "error") {
        return Err(failure(
            "Состояние WinDivert не определено.",
            "Файлы не заменены.".into(),
        ));
    }
    let guards = crate::driver::quiesce_for_update(current)?;
    drop(guards);
    Ok(())
}

fn mode(before: Option<&RuntimeSnapshot>) -> RestoredMode {
    if before.is_some() {
        RestoredMode::Manual
    } else {
        RestoredMode::Stopped
    }
}

fn plain_directory_exists(path: &Path) -> Result<bool, AppError> {
    match fs::symlink_metadata(path) {
        Ok(value) if value.is_dir() && !value.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(failure(
            "Путь движка имеет недопустимый тип.",
            path.display().to_string(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(failure(
            "Не удалось проверить путь движка.",
            error.to_string(),
        )),
    }
}

/// Copy only known mutable files, never BATs, executables, or release lists.
fn preserve_engine_customization(current: &Path, stage: &Path) -> Result<(), AppError> {
    for folder in ["lists", "bin", "utils"] {
        let source = current.join(folder);
        if !plain_directory_exists(&source)? {
            continue;
        }
        for entry in fs::read_dir(&source).map_err(|error| {
            failure(
                "Не удалось прочитать пользовательские файлы.",
                error.to_string(),
            )
        })? {
            let entry = entry.map_err(|error| {
                failure(
                    "Не удалось прочитать пользовательский файл.",
                    error.to_string(),
                )
            })?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                failure(
                    "Имя пользовательского файла нельзя безопасно перенести.",
                    folder.to_owned(),
                )
            })?;
            let target = stage.join(folder).join(name);
            let target_exists = match fs::symlink_metadata(&target) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
                Ok(_) => {
                    return Err(failure(
                        "Файл в обновлении имеет недопустимый тип.",
                        target.display().to_string(),
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => {
                    return Err(failure(
                        "Не удалось проверить файл в обновлении.",
                        error.to_string(),
                    ))
                }
            };
            let extra_data = !target_exists && user_extra_file(folder, name);
            if !mutable_engine_file(folder, name) && !extra_data {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                failure(
                    "Не удалось проверить пользовательский файл.",
                    error.to_string(),
                )
            })?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > 32 * 1024 * 1024
            {
                return Err(failure(
                    "Пользовательский файл имеет недопустимый тип или размер.",
                    name.to_owned(),
                ));
            }
            if !plain_directory_exists(&stage.join(folder))? {
                return Err(failure(
                    "В обновлении отсутствует папка пользовательских файлов.",
                    folder.to_owned(),
                ));
            }
            fs::copy(entry.path(), target).map_err(|error| {
                failure(
                    "Не удалось перенести пользовательский файл.",
                    format!("{name}: {error}"),
                )
            })?;
        }
    }
    Ok(())
}

fn mutable_engine_file(folder: &str, name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    match folder {
        "lists" => {
            name.ends_with("-user.txt")
                || matches!(name.as_str(), "ipset-all.txt" | "ipset-all.txt.backup")
        }
        "bin" => matches!(
            name.as_str(),
            "active_discord_udp.bin" | "active_game_udp.bin"
        ),
        "utils" => matches!(
            name.as_str(),
            "game_filter.enabled" | "check_updates.enabled"
        ),
        _ => false,
    }
}

fn user_extra_file(folder: &str, name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !name.starts_with('.')
        && match folder {
            "lists" => name.ends_with(".txt"),
            "bin" => name.ends_with(".bin"),
            _ => false,
        }
}

fn release_label(current: &Path) -> String {
    fs::read_to_string(current.join(".service").join("version.txt"))
        .map(|value| value.trim().to_owned())
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Сохранённая версия".into())
}

fn combine_recovery(error: AppError, recovery: Result<(), AppError>) -> AppError {
    match recovery {
        Ok(()) => error,
        Err(recovery) => failure(
            "Обновление не завершено; восстановление требует вмешательства.",
            format!(
                "Причина: {}. Восстановление: {}",
                error.detail.as_deref().unwrap_or(&error.message),
                recovery.detail.as_deref().unwrap_or(&recovery.message)
            ),
        ),
    }
}

fn cleanup_warning(error: AppError) -> AppError {
    AppError::new(
        "update_cleanup_pending",
        "Версия восстановлена, но очистка прежних файлов не завершена.",
        "Повторите операцию после проверки блокировок файлов.",
    )
    .with_detail(error.detail.unwrap_or(error.message))
}

fn validate_operation_id(value: &str) -> Result<(), AppError> {
    if value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        Ok(())
    } else {
        Err(failure(
            "Идентификатор обновления имеет неверный формат.",
            "Операция не начата.".into(),
        ))
    }
}

fn emit<F: FnMut(EngineUpdateProgress)>(
    report: &mut F,
    operation_id: &str,
    sequence: &mut u64,
    stage: UpdateStage,
    state: UpdateProgressState,
    message: &str,
    detail: Option<String>,
) {
    *sequence += 1;
    report(EngineUpdateProgress {
        operation_id: operation_id.to_owned(),
        sequence: *sequence,
        stage,
        state,
        message: message.to_owned(),
        detail,
    });
}

fn emit_error<F: FnMut(EngineUpdateProgress)>(
    report: &mut F,
    id: &str,
    sequence: &mut u64,
    stage: UpdateStage,
    error: &AppError,
) {
    emit(
        report,
        id,
        sequence,
        stage,
        UpdateProgressState::Failed,
        &error.message,
        error.detail.clone(),
    );
}

fn failure(message: &'static str, detail: String) -> AppError {
    AppError::new(
        "engine_update_failed",
        message,
        "Проверьте состояние движка и повторите операцию.",
    )
    .with_detail(detail)
}

#[cfg(windows)]
pub(crate) fn acquire_update_lock(parent: &Path) -> Result<fs::File, AppError> {
    use std::os::windows::fs::OpenOptionsExt;
    let path = parent.join(".zapret-update.lock");
    match fs::symlink_metadata(&path) {
        Ok(value) if value.file_type().is_symlink() || !value.is_file() => {
            return Err(failure(
                "Файл блокировки обновления имеет неверный тип.",
                path.display().to_string(),
            ))
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(failure(
                "Не удалось проверить блокировку обновления.",
                error.to_string(),
            ))
        }
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(0)
        .open(path)
        .map_err(|error| failure("Другое обновление уже выполняется.", error.to_string()))
}

#[cfg(not(windows))]
pub(crate) fn acquire_update_lock(_parent: &Path) -> Result<fs::File, AppError> {
    Err(failure(
        "Обновление доступно только в Windows.",
        "Операция не начата.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn mutable_files_are_explicit_and_do_not_include_release_code() {
        for name in [
            "list-general-user.txt",
            "ipset-exclude-user.txt",
            "ipset-all.txt.backup",
        ] {
            assert!(mutable_engine_file("lists", name));
        }
        assert!(mutable_engine_file("bin", "ACTIVE_GAME_UDP.bin"));
        assert!(mutable_engine_file("utils", "game_filter.enabled"));
        for (folder, name) in [
            ("bin", "winws.exe"),
            ("bin", "WinDivert.dll"),
            ("lists", "list-general.txt"),
            ("utils", "test zapret.ps1"),
            ("root", "general.bat"),
        ] {
            assert!(!mutable_engine_file(folder, name));
        }
    }

    #[test]
    fn update_id_is_a_uuid_shape_only() {
        assert!(validate_operation_id("8b22f5ef-120f-4a9d-852b-2226e276515e").is_ok());
        assert!(validate_operation_id("../current").is_err());
    }

    #[test]
    fn preservation_copies_mutable_files_without_overwriting_release_files() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("zapret-preserve-{nonce}"));
        let old = root.join("old");
        let stage = root.join("stage");
        for folder in ["lists", "bin", "utils"] {
            fs::create_dir_all(old.join(folder)).unwrap();
            fs::create_dir_all(stage.join(folder)).unwrap();
        }
        fs::write(old.join("lists/list-general-user.txt"), b"my.example\n").unwrap();
        fs::write(old.join("lists/my-extra-list.txt"), b"extra.example\n").unwrap();
        fs::write(old.join("lists/list-general.txt"), b"old official\n").unwrap();
        fs::write(stage.join("lists/list-general.txt"), b"new official\n").unwrap();
        fs::write(old.join("bin/ACTIVE_GAME_UDP.bin"), b"chosen fake").unwrap();
        fs::write(old.join("utils/game_filter.enabled"), b"mode=all\n").unwrap();
        preserve_engine_customization(&old, &stage).unwrap();
        assert_eq!(
            fs::read(stage.join("lists/list-general-user.txt")).unwrap(),
            b"my.example\n"
        );
        assert_eq!(
            fs::read(stage.join("lists/my-extra-list.txt")).unwrap(),
            b"extra.example\n"
        );
        assert_eq!(
            fs::read(stage.join("bin/ACTIVE_GAME_UDP.bin")).unwrap(),
            b"chosen fake"
        );
        assert_eq!(
            fs::read(stage.join("utils/game_filter.enabled")).unwrap(),
            b"mode=all\n"
        );
        assert_eq!(
            fs::read(stage.join("lists/list-general.txt")).unwrap(),
            b"new official\n"
        );
        let _ = fs::remove_dir_all(root);
    }
}
