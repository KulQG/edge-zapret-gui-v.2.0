//! Filesystem-only primitives for safely staging and promoting a zapret engine.
//!
//! This module does not download archives, stop processes or services, or request
//! elevation. Callers must provide paths under the trusted engine directory.

use crate::error::AppError;
use crate::strategy;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

const JOURNAL_NAME: &str = ".zapret-update-transaction.json";
const JOURNAL_TEMP_NAME: &str = ".zapret-update-transaction.json.tmp";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct TransactionJournal {
    version: u32,
    stage_name: String,
    current_name: String,
    rollback_name: String,
    phase: TransactionPhase,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum TransactionPhase {
    InitialPrepared,
    InitialPromoting,
    InitialPromoted,
    InitialMovingBack,
    InitialRolledBack,
    Prepared,
    MovingCurrentToRollback,
    CurrentMovedToRollback,
    PromotingStage,
    Promoted,
    // The restored mode is healthy and the previous release remains available
    // for a user-requested rollback.
    Retained,
    // Runtime restoration has succeeded. The previous directory may already
    // be partly deleted, so this phase must never permit a rollback.
    Committed,
    MovingPromotedToStage,
    PromotedMovedToStage,
    RestoringRollback,
    RolledBack,
    UserMovingPromotedToStage,
    UserPromotedMovedToStage,
    UserRestoringRollback,
    UserRolledBack,
    UndoingUserRollback,
    UserRollbackCurrentMoved,
    // The superseded engine in stage may be partly deleted.
    UserRollbackCommitted,
}

/// Validate static release structure and discover top-level strategy BAT files.
/// The official BAT prepares its runtime files when it is launched.
pub fn validate_staged_engine(
    root: &Path,
    required_strategy: Option<&str>,
) -> Result<(), AppError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|error| {
        update_error(
            "update_stage_invalid",
            "Не удалось проверить подготовленные файлы zapret.",
            format!("Не удалось открыть папку обновления: {error}"),
        )
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(update_error(
            "update_stage_invalid",
            "Папка обновления zapret имеет неверный формат.",
            "Корень подготовленного движка не является обычной папкой.".to_owned(),
        ));
    }
    let canonical = fs::canonicalize(root).map_err(|error| {
        update_error(
            "update_stage_invalid",
            "Не удалось проверить подготовленные файлы zapret.",
            format!("Не удалось открыть папку обновления: {error}"),
        )
    })?;
    if !canonical.is_dir() {
        return Err(update_error(
            "update_stage_invalid",
            "Папка обновления zapret имеет неверный формат.",
            "Корень подготовленного движка не является папкой.".to_owned(),
        ));
    }

    let required_files = [
        canonical.join("bin").join("winws.exe"),
        canonical.join("bin").join("WinDivert.dll"),
        canonical.join("service.bat"),
    ];
    let missing: Vec<String> = required_files
        .iter()
        .filter(|path| !is_regular_file(path))
        .map(|path| relative_display(&canonical, path))
        .collect();
    let driver_present = ["WinDivert64.sys", "WinDivert32.sys"]
        .iter()
        .any(|name| is_regular_file(&canonical.join("bin").join(name)));
    let lists_present = is_plain_directory(&canonical.join("lists"));
    if !missing.is_empty() || !driver_present || !lists_present {
        let mut absent = missing;
        if !driver_present {
            absent.push("bin/WinDivert64.sys или bin/WinDivert32.sys".to_owned());
        }
        if !lists_present {
            absent.push("lists/".to_owned());
        }
        return Err(update_error(
            "update_stage_invalid",
            "В подготовленном обновлении отсутствуют необходимые файлы.",
            format!("Не найдены: {}.", absent.join(", ")),
        ));
    }

    let discovered = strategy::discover_strategies(&canonical).map_err(|error| {
        update_error(
            "update_strategy_discovery_failed",
            "Не удалось проверить файлы стратегий в подготовленном обновлении.",
            format!("{} {}", error.message, error.detail.unwrap_or_default()),
        )
    })?;
    if !discovered.iter().any(|entry| entry.summary.supported) {
        return Err(update_error(
            "update_strategy_unsupported",
            "В обновлении нет доступного файла стратегии.",
            "В корне релиза нужен проверенный файл general*.bat.".to_owned(),
        ));
    }
    if let Some(required) = required_strategy {
        let found = discovered
            .iter()
            .any(|entry| entry.summary.id == required && entry.summary.supported);
        if !found {
            return Err(update_error(
                "update_required_strategy_missing",
                "Нельзя восстановить выбранную стратегию после обновления.",
                format!("Файл стратегии «{required}» отсутствует или недоступен в новой версии."),
            ));
        }
    }
    Ok(())
}

/// Promote a validated stage directory to `current`, retaining the previous
/// engine at `rollback`. All paths must be direct children of the same existing
/// trusted parent directory; a transaction journal is retained for recovery.
///
/// On failure to move the stage into place, the previous engine is restored
/// before returning when the filesystem permits that recovery rename.
pub fn promote_engine(stage: &Path, current: &Path, rollback: &Path) -> Result<(), AppError> {
    promote_engine_with_rename(stage, current, rollback, |from, to| fs::rename(from, to))
}

/// Install into an absent `current` without inventing a previous engine.
/// The journal is durable before the single same-volume directory rename.
pub fn promote_initial_engine(stage: &Path, current: &Path) -> Result<(), AppError> {
    promote_initial_engine_with_rename(stage, current, |from, to| fs::rename(from, to))
}

fn promote_initial_engine_with_rename<F>(
    stage: &Path,
    current: &Path,
    mut rename: F,
) -> Result<(), AppError>
where
    F: FnMut(&Path, &Path) -> io::Result<()>,
{
    validate_staged_engine(stage, None)?;
    let rollback = initial_reserved_rollback(current)?;
    let paths = validate_transaction_paths(stage, current, &rollback, false)?;
    let current = paths.parent.join(file_name_string(current)?);
    let stage = paths.parent.join(file_name_string(stage)?);
    let rollback = paths.parent.join(file_name_string(&rollback)?);
    let journal_path = paths.parent.join(JOURNAL_NAME);
    if path_exists_or_link(&journal_path)?
        || path_exists_or_link(&paths.parent.join(JOURNAL_TEMP_NAME))?
        || path_exists_or_link(&current)?
        || path_exists_or_link(&rollback)?
    {
        return Err(transaction_error(
            "Первая установка требует пустую текущую папку и отсутствие незавершённой транзакции."
                .to_owned(),
        ));
    }
    let mut journal = TransactionJournal {
        version: 1,
        stage_name: file_name_string(&stage)?,
        current_name: file_name_string(&current)?,
        rollback_name: file_name_string(&rollback)?,
        phase: TransactionPhase::InitialPrepared,
    };
    write_journal(&journal_path, &journal)?;
    journal.phase = TransactionPhase::InitialPromoting;
    write_journal(&journal_path, &journal)?;
    rename(&stage, &current).map_err(|error| {
        transaction_error(format!(
            "Не удалось установить проверенный движок: {error}. Подготовленные файлы сохранены."
        ))
    })?;
    journal.phase = TransactionPhase::InitialPromoted;
    write_journal(&journal_path, &journal)
}

/// Return a newly promoted engine to its stage when post-install validation
/// fails. A failed rename leaves the journal and both paths for recovery.
pub fn rollback_initial_engine(current: &Path) -> Result<(), AppError> {
    let paths = sibling_paths_from_current(current)?;
    let current = paths.parent.join(file_name_string(current)?);
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let mut journal = read_journal(&journal_path)?;
    if !is_initial_phase(journal.phase)
        || journal.current_name != file_name_string(&current)?
        || journal.rollback_name != file_name_string(&initial_reserved_rollback(&current)?)?
    {
        return Err(transaction_error(
            "Запись первой установки не соответствует текущей папке.".to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    let rollback = paths.parent.join(&journal.rollback_name);
    validate_transaction_paths(&stage, &current, &rollback, true)?;
    if path_exists_or_link(&rollback)? {
        return Err(transaction_error(
            "Во время первой установки появилась резервная папка; файлы не перемещены.".to_owned(),
        ));
    }
    if path_exists_or_link(&current)? {
        if path_exists_or_link(&stage)? {
            return Err(transaction_error(
                "Текущая и подготовленная папки существуют одновременно; восстановление остановлено."
                    .to_owned(),
            ));
        }
        journal.phase = TransactionPhase::InitialMovingBack;
        write_journal(&journal_path, &journal)?;
        fs::rename(&current, &stage).map_err(|error| {
            transaction_error(format!(
                "Не удалось сохранить новую папку для восстановления: {error}"
            ))
        })?;
    }
    if !stage.is_dir() || path_exists_or_link(&current)? {
        return Err(transaction_error(
            "Не удалось подтвердить отсутствие текущего движка после отмены первой установки."
                .to_owned(),
        ));
    }
    journal.phase = TransactionPhase::InitialRolledBack;
    write_journal(&journal_path, &journal)
}

/// Complete a first installation only after validating the promoted engine.
pub fn finalize_initial_engine(current: &Path) -> Result<(), AppError> {
    let paths = sibling_paths_from_current(current)?;
    let current = paths.parent.join(file_name_string(current)?);
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let journal = read_journal(&journal_path)?;
    if journal.phase != TransactionPhase::InitialPromoted
        || journal.current_name != file_name_string(&current)?
        || journal.rollback_name != file_name_string(&initial_reserved_rollback(&current)?)?
    {
        return Err(transaction_error(
            "Первая установка не подтверждена записью транзакции.".to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    let rollback = paths.parent.join(&journal.rollback_name);
    validate_transaction_paths(&stage, &current, &rollback, true)?;
    if path_exists_or_link(&stage)? || path_exists_or_link(&rollback)? {
        return Err(transaction_error(
            "Подготовленная или резервная папка неожиданно существует; установка не завершена."
                .to_owned(),
        ));
    }
    validate_staged_engine(&current, None)?;
    fs::remove_file(journal_path).map_err(|error| {
        transaction_error(format!(
            "Не удалось закрыть запись первой установки: {error}"
        ))
    })
}

fn initial_reserved_rollback(current: &Path) -> Result<PathBuf, AppError> {
    Ok(current
        .parent()
        .ok_or_else(|| path_error("У папки движка нет родительского пути.".to_owned()))?
        .join(".rollback-initial-reserved"))
}

fn is_initial_phase(phase: TransactionPhase) -> bool {
    matches!(
        phase,
        TransactionPhase::InitialPrepared
            | TransactionPhase::InitialPromoting
            | TransactionPhase::InitialPromoted
            | TransactionPhase::InitialMovingBack
            | TransactionPhase::InitialRolledBack
    )
}

/// Let the orchestrator verify that no process/service is using a prior
/// interrupted first install before recovery moves its directory.
pub fn initial_install_recovery_pending(current: &Path) -> Result<bool, AppError> {
    let paths = sibling_paths_from_current(current)?;
    let journal_path = paths.parent.join(JOURNAL_NAME);
    if !path_exists_or_link(&journal_path)? {
        return Ok(false);
    }
    let journal = read_journal(&journal_path)?;
    Ok(is_initial_phase(journal.phase))
}

/// Restore the previous engine using the retained transaction journal. The new
/// engine is moved back to its original stage name instead of being deleted.
pub fn rollback_engine(current: &Path, rollback: &Path) -> Result<(), AppError> {
    rollback_engine_inner(current, rollback, false)
}

/// Swap the current release with the retained previous release. The journal
/// remains until the caller confirms that its former mode runs successfully.
pub fn rollback_retained_engine(current: &Path) -> Result<(), AppError> {
    let rollback = retained_engine_rollback(current)?
        .ok_or_else(|| transaction_error("Нет сохранённой версии для отката.".to_owned()))?;
    rollback_engine_inner(current, &rollback, true)
}

/// Retry an interrupted user rollback while the runtime is stopped. A completed
/// swap is left pending for the caller to restore the prior mode or undo it.
pub fn resume_retained_rollback(current: &Path) -> Result<(), AppError> {
    let paths = sibling_paths_from_current(current)?;
    let journal = read_journal(&paths.parent.join(JOURNAL_NAME))?;
    if journal.current_name != file_name_string(current)? {
        return Err(transaction_error(
            "Запись отката относится к другой папке движка.".to_owned(),
        ));
    }
    if journal.phase == TransactionPhase::UserRolledBack {
        return Ok(());
    }
    if !matches!(
        journal.phase,
        TransactionPhase::UserMovingPromotedToStage
            | TransactionPhase::UserPromotedMovedToStage
            | TransactionPhase::UserRestoringRollback
    ) {
        return Err(transaction_error(
            "Пользовательский откат не находится в состоянии восстановления.".to_owned(),
        ));
    }
    let rollback = paths.parent.join(journal.rollback_name);
    rollback_engine_inner(current, &rollback, true)
}

fn rollback_engine_inner(
    current: &Path,
    rollback: &Path,
    user_rollback: bool,
) -> Result<(), AppError> {
    let paths = sibling_paths_from_current(current)?;
    let rollback_parent = canonical_parent(rollback)?;
    if rollback_parent != paths.parent {
        return Err(path_error(
            "Папки движка и резервной копии должны находиться рядом.".to_owned(),
        ));
    }
    // `canonicalize(parent)` may return an extended Windows path (`\\?\...`).
    // Normalize both children under that parent before comparing or renaming.
    let current = paths.parent.join(file_name_string(current)?);
    let rollback = paths.parent.join(file_name_string(rollback)?);
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let mut journal = read_journal(&journal_path)?;
    if matches!(
        journal.phase,
        TransactionPhase::Committed | TransactionPhase::UserRollbackCommitted
    ) {
        return Err(transaction_error(
            "Обновление уже подтверждено; откат к удаляемой резервной копии запрещён.".to_owned(),
        ));
    }
    if user_rollback
        && !matches!(
            journal.phase,
            TransactionPhase::Retained
                | TransactionPhase::UserMovingPromotedToStage
                | TransactionPhase::UserPromotedMovedToStage
                | TransactionPhase::UserRestoringRollback
                | TransactionPhase::UserRolledBack
        )
    {
        return Err(transaction_error(
            "Пользовательский откат не подтверждён сохранённой версией.".to_owned(),
        ));
    }
    if !user_rollback && journal.phase == TransactionPhase::Retained {
        return Err(transaction_error(
            "Сохранённая версия требует явного пользовательского отката.".to_owned(),
        ));
    }
    if journal.current_name != file_name_string(&current)?
        || journal.rollback_name != file_name_string(&rollback)?
    {
        return Err(transaction_error(
            "Файл восстановления относится к другим папкам движка.".to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    validate_transaction_paths(&stage, &current, &rollback, true)?;

    let current_exists = current.exists();
    let rollback_exists = rollback.exists();
    if !rollback_exists {
        if user_rollback
            && matches!(
                journal.phase,
                TransactionPhase::UserRestoringRollback | TransactionPhase::UserRolledBack
            )
            && current_exists
            && stage.is_dir()
        {
            journal.phase = TransactionPhase::UserRolledBack;
            write_journal(&journal_path, &journal)?;
            return Ok(());
        }
        if current_exists && journal.phase == TransactionPhase::RolledBack {
            return Ok(());
        }
        return Err(transaction_error(
            "Папка с предыдущим движком отсутствует; файлы не перемещены.".to_owned(),
        ));
    }
    if !current_exists && !stage.is_dir() {
        return Err(transaction_error(
            "Текущая и подготовленная папки отсутствуют; восстановление остановлено.".to_owned(),
        ));
    }
    if current_exists {
        if stage.exists() {
            return Err(transaction_error(
                "Папка текущего движка и папка подготовки уже существуют одновременно; восстановление остановлено.".to_owned(),
            ));
        }
        journal.phase = if user_rollback {
            TransactionPhase::UserMovingPromotedToStage
        } else {
            TransactionPhase::MovingPromotedToStage
        };
        write_journal(&journal_path, &journal)?;
        fs::rename(&current, &stage).map_err(|error| {
            transaction_error(format!(
                "Не удалось сохранить новую папку движка перед откатом: {error}"
            ))
        })?;
        journal.phase = if user_rollback {
            TransactionPhase::UserPromotedMovedToStage
        } else {
            TransactionPhase::PromotedMovedToStage
        };
        write_journal(&journal_path, &journal)?;
    }
    journal.phase = if user_rollback {
        TransactionPhase::UserRestoringRollback
    } else {
        TransactionPhase::RestoringRollback
    };
    write_journal(&journal_path, &journal)?;
    fs::rename(&rollback, &current).map_err(|error| {
        transaction_error(format!(
            "Не удалось вернуть предыдущую папку движка: {error}"
        ))
    })?;
    journal.phase = if user_rollback {
        TransactionPhase::UserRolledBack
    } else {
        TransactionPhase::RolledBack
    };
    write_journal(&journal_path, &journal)
}

/// Return the previous release only after the update's restored mode has been
/// confirmed. A missing journal means there is no user rollback to offer.
pub fn retained_engine_rollback(current: &Path) -> Result<Option<PathBuf>, AppError> {
    let paths = sibling_paths_from_current(current)?;
    let journal_path = paths.parent.join(JOURNAL_NAME);
    if !path_exists_or_link(&journal_path)? {
        return Ok(None);
    }
    let journal = read_journal(&journal_path)?;
    if journal.phase != TransactionPhase::Retained {
        return Ok(None);
    }
    if journal.current_name != file_name_string(current)? {
        return Err(transaction_error(
            "Запись отката относится к другой текущей папке движка.".to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    let rollback = paths.parent.join(&journal.rollback_name);
    validate_transaction_paths(&stage, current, &rollback, true)?;
    if !current.is_dir() || !rollback.is_dir() || path_exists_or_link(&stage)? {
        return Err(transaction_error(
            "Сохранённая версия недоступна; откат не начат.".to_owned(),
        ));
    }
    Ok(Some(rollback))
}

/// Commit a successful update without deleting the previous release. The
/// durable journal makes that release discoverable after a GUI restart.
pub fn commit_engine_update_retaining_rollback(
    current: &Path,
    rollback: &Path,
) -> Result<(), AppError> {
    let paths = sibling_paths_from_current(current)?;
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let mut journal = read_journal(&journal_path)?;
    if journal.phase != TransactionPhase::Promoted
        || journal.current_name != file_name_string(current)?
        || journal.rollback_name != file_name_string(rollback)?
    {
        return Err(transaction_error(
            "Нельзя сохранить резервную копию: обновление ещё не подтверждено.".to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    validate_transaction_paths(&stage, current, rollback, true)?;
    if !current.is_dir() || !rollback.is_dir() || path_exists_or_link(&stage)? {
        return Err(transaction_error(
            "Текущая или резервная папка отсутствует; файлы не изменены.".to_owned(),
        ));
    }
    validate_staged_engine(current, None)?;
    journal.phase = TransactionPhase::Retained;
    write_journal(&journal_path, &journal)
}

/// Before another replacement, release an older retained backup. The journal
/// first crosses the durable Committed boundary; interrupted cleanup can then
/// resume without ever rolling back to a partly deleted directory.
pub fn release_retained_engine_update(current: &Path) -> Result<(), AppError> {
    let rollback = retained_engine_rollback(current)?
        .ok_or_else(|| transaction_error("Нет сохранённой версии для очистки.".to_owned()))?;
    finalize_engine_update(current, &rollback)
}

/// If restarting the previous release failed, return to the release that ran
/// before the user requested rollback. Each rename has a journaled phase.
pub fn undo_retained_rollback(current: &Path) -> Result<(), AppError> {
    let paths = sibling_paths_from_current(current)?;
    let current = paths.parent.join(file_name_string(current)?);
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let mut journal = read_journal(&journal_path)?;
    if journal.current_name != file_name_string(&current)?
        || !matches!(
            journal.phase,
            TransactionPhase::UserRolledBack
                | TransactionPhase::UndoingUserRollback
                | TransactionPhase::UserRollbackCurrentMoved
        )
    {
        return Err(transaction_error(
            "Нельзя вернуть новую версию: пользовательский откат не ожидает восстановления."
                .to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    let rollback = paths.parent.join(&journal.rollback_name);
    validate_transaction_paths(&stage, &current, &rollback, true)?;

    if journal.phase == TransactionPhase::UserRolledBack {
        if !current.is_dir() || !stage.is_dir() || path_exists_or_link(&rollback)? {
            return Err(transaction_error(
                "Папки после отката изменились; автоматическое восстановление остановлено."
                    .to_owned(),
            ));
        }
        journal.phase = TransactionPhase::UndoingUserRollback;
        write_journal(&journal_path, &journal)?;
    }
    if journal.phase == TransactionPhase::UndoingUserRollback {
        if current.is_dir() && stage.is_dir() && !path_exists_or_link(&rollback)? {
            fs::rename(&current, &rollback).map_err(|error| {
                transaction_error(format!("Не удалось сохранить откатанную версию: {error}"))
            })?;
        }
        if path_exists_or_link(&current)? || !stage.is_dir() || !rollback.is_dir() {
            return Err(transaction_error(
                "Не удалось подтвердить состояние папок при отмене отката.".to_owned(),
            ));
        }
        journal.phase = TransactionPhase::UserRollbackCurrentMoved;
        write_journal(&journal_path, &journal)?;
    }
    if !path_exists_or_link(&current)? && stage.is_dir() && rollback.is_dir() {
        fs::rename(&stage, &current).map_err(|error| {
            transaction_error(format!("Не удалось вернуть новую версию: {error}"))
        })?;
    }
    if !current.is_dir() || !rollback.is_dir() || path_exists_or_link(&stage)? {
        return Err(transaction_error(
            "Не удалось подтвердить восстановление версии до отката.".to_owned(),
        ));
    }
    journal.phase = TransactionPhase::Retained;
    write_journal(&journal_path, &journal)
}

/// Complete a user rollback after its former mode runs. The superseded new
/// release is removed only after the durable no-undo boundary is recorded.
pub fn finalize_retained_rollback(current: &Path) -> Result<(), AppError> {
    let paths = sibling_paths_from_current(current)?;
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let mut journal = read_journal(&journal_path)?;
    if journal.current_name != file_name_string(current)?
        || !matches!(
            journal.phase,
            TransactionPhase::UserRolledBack | TransactionPhase::UserRollbackCommitted
        )
    {
        return Err(transaction_error(
            "Пользовательский откат ещё не завершил восстановление режима.".to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    let rollback = paths.parent.join(&journal.rollback_name);
    validate_transaction_paths(&stage, current, &rollback, true)?;
    if !current.is_dir()
        || path_exists_or_link(&rollback)?
        || (journal.phase == TransactionPhase::UserRolledBack && !stage.is_dir())
    {
        return Err(transaction_error(
            "Папки пользовательского отката изменились; очистка остановлена.".to_owned(),
        ));
    }
    validate_staged_engine(current, None)?;
    if journal.phase == TransactionPhase::UserRolledBack {
        journal.phase = TransactionPhase::UserRollbackCommitted;
        write_journal(&journal_path, &journal)?;
    }
    if path_exists_or_link(&stage)? {
        fs::remove_dir_all(&stage).map_err(|error| {
            transaction_error(format!("Не удалось удалить заменённую версию: {error}"))
        })?;
    }
    fs::remove_file(&journal_path)
        .map_err(|error| transaction_error(format!("Не удалось закрыть запись отката: {error}")))
}

/// Tell the orchestrator whether a failed finalization crossed the durable
/// no-undo boundary. Cleanup errors after this point are warnings; errors
/// before it must leave the rollback pending.
pub fn user_rollback_committed(current: &Path) -> Result<bool, AppError> {
    let paths = sibling_paths_from_current(current)?;
    let journal_path = paths.parent.join(JOURNAL_NAME);
    if !path_exists_or_link(&journal_path)? {
        return Ok(false);
    }
    let journal = read_journal(&journal_path)?;
    if journal.current_name != file_name_string(current)? {
        return Err(transaction_error(
            "Запись отката относится к другой текущей папке движка.".to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    let rollback = paths.parent.join(&journal.rollback_name);
    validate_transaction_paths(&stage, current, &rollback, true)?;
    if journal.phase == TransactionPhase::UserRollbackCommitted
        && (!current.is_dir() || path_exists_or_link(&rollback)?)
    {
        return Err(transaction_error(
            "Подтверждённый откат содержит неожиданное состояние папок.".to_owned(),
        ));
    }
    Ok(journal.phase == TransactionPhase::UserRollbackCommitted)
}

/// Recover a transaction interrupted before its promotion was recorded as
/// complete. Returns the preserved stage directory when recovery restored the
/// previous engine. A completed promotion is left intact for runtime checks.
pub fn recover_engine_update(current: &Path) -> Result<Option<PathBuf>, AppError> {
    let paths = sibling_paths_from_current(current)?;
    let current_name = file_name_string(current)?;
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let temp_path = paths.parent.join(JOURNAL_TEMP_NAME);
    match fs::symlink_metadata(&journal_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A journal temp can only be left before its atomic rename. Engine
            // mutations begin only after the journal rename has completed.
            match fs::symlink_metadata(&temp_path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    fs::remove_file(&temp_path).map_err(|error| {
                        transaction_error(format!(
                            "Не удалось удалить незавершённую запись обновления: {error}"
                        ))
                    })?;
                }
                Ok(_) => {
                    return Err(transaction_error(
                        "Временная запись обновления имеет небезопасный тип.".to_owned(),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(transaction_error(format!(
                        "Не удалось проверить временную запись обновления: {error}"
                    )))
                }
            }
            return Ok(None);
        }
        Err(error) => {
            return Err(transaction_error(format!(
                "Не удалось проверить запись обновления: {error}"
            )))
        }
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(transaction_error(
                "Запись обновления должна быть обычным файлом.".to_owned(),
            ));
        }
        Ok(_) => {}
    }

    let journal = read_journal(&journal_path)?;
    if journal.current_name != current_name {
        return Err(transaction_error(
            "Запись обновления относится к другой текущей папке движка.".to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    let rollback = paths.parent.join(&journal.rollback_name);
    validate_transaction_paths(&stage, current, &rollback, true)?;
    // A leftover temp is stale once the authoritative journal exists. Remove
    // it before rollback so the journal can be rewritten at each rename.
    match fs::symlink_metadata(&temp_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(&temp_path).map_err(|error| {
                transaction_error(format!(
                    "Не удалось удалить временную запись перед восстановлением: {error}"
                ))
            })?;
        }
        Ok(_) => {
            return Err(transaction_error(
                "Временная запись обновления имеет небезопасный тип.".to_owned(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(transaction_error(format!(
                "Не удалось проверить временную запись обновления: {error}"
            )))
        }
    }

    if is_initial_phase(journal.phase) {
        if journal.rollback_name != file_name_string(&initial_reserved_rollback(current)?)? {
            return Err(transaction_error(
                "Запись первой установки содержит неверную резервную папку.".to_owned(),
            ));
        }
        rollback_initial_engine(current)?;
        fs::remove_file(&journal_path).map_err(|error| {
            transaction_error(format!(
                "Первая установка отменена, но не удалось закрыть запись восстановления: {error}"
            ))
        })?;
        return Ok(Some(stage));
    }

    if journal.phase == TransactionPhase::Committed {
        // Destructive backup cleanup may have been interrupted halfway through.
        // Retry only that cleanup, keeping the healthy current engine intact.
        finalize_engine_update(current, &rollback)?;
        return Ok(None);
    }
    if journal.phase == TransactionPhase::UserRollbackCommitted {
        finalize_retained_rollback(current)?;
        return Ok(None);
    }

    if matches!(
        journal.phase,
        TransactionPhase::UndoingUserRollback | TransactionPhase::UserRollbackCurrentMoved
    ) {
        undo_retained_rollback(current)?;
        return Ok(None);
    }

    if matches!(
        journal.phase,
        TransactionPhase::UserMovingPromotedToStage
            | TransactionPhase::UserPromotedMovedToStage
            | TransactionPhase::UserRestoringRollback
    ) {
        rollback_engine_inner(current, &rollback, true)?;
    }
    if matches!(
        journal.phase,
        TransactionPhase::UserMovingPromotedToStage
            | TransactionPhase::UserPromotedMovedToStage
            | TransactionPhase::UserRestoringRollback
            | TransactionPhase::UserRolledBack
    ) {
        return Err(update_error(
            "update_runtime_recovery_pending",
            "Откат версии ожидает восстановления прежнего режима.",
            "Проверьте запуск прежней стратегии и завершите или отмените откат.".to_owned(),
        ));
    }

    if journal.phase == TransactionPhase::Retained {
        retained_engine_rollback(current)?;
        return Ok(None);
    }

    if journal.phase == TransactionPhase::Promoted {
        if !current.is_dir() {
            return Err(transaction_error(
                "Обновление отмечено завершённым, но текущая папка движка отсутствует; файлы не перемещены.".to_owned(),
            ));
        }
        if rollback.exists() {
            return Err(update_error(
                "update_runtime_recovery_pending",
                "Предыдущее обновление ещё не завершило восстановление рабочего режима.",
                format!(
                    "Резервная копия сохранена в {}. Проверьте состояние службы или временного режима и завершите восстановление перед новым обновлением.",
                    rollback.display()
                ),
            ));
        }
        fs::remove_file(&journal_path).map_err(|error| {
            transaction_error(format!(
                "Движок обновлён и резервная папка отсутствует, но не удалось удалить запись транзакции: {error}"
            ))
        })?;
        return Ok(None);
    }

    if rollback.exists() {
        rollback_engine(current, &rollback)?;
    } else if current.is_dir()
        && stage.is_dir()
        && matches!(
            journal.phase,
            TransactionPhase::Prepared
                | TransactionPhase::MovingCurrentToRollback
                | TransactionPhase::RestoringRollback
                | TransactionPhase::RolledBack
        )
    {
        // The current-to-rollback rename had not happened, or rollback had
        // already completed before the process exited.
    } else {
        return Err(transaction_error(
            "Состояние папок не позволяет безопасно определить предыдущий движок; файлы не удалены.".to_owned(),
        ));
    }

    if !current.is_dir() || !stage.is_dir() || rollback.exists() {
        return Err(transaction_error(
            "После восстановления не удалось подтвердить расположение папок движка.".to_owned(),
        ));
    }
    fs::remove_file(&journal_path).map_err(|error| {
        transaction_error(format!(
            "Движок восстановлен, но не удалось удалить запись транзакции: {error}"
        ))
    })?;
    Ok(Some(stage))
}

/// Remove the retained previous engine after the caller has confirmed the
/// restored runtime is healthy. This function only accepts a completed,
/// journaled promotion and never deletes the current engine.
pub fn finalize_engine_update(current: &Path, rollback: &Path) -> Result<(), AppError> {
    finalize_engine_update_with_cleanup(
        current,
        rollback,
        |path| fs::remove_dir_all(path),
        |path| fs::remove_file(path),
    )
}

fn finalize_engine_update_with_cleanup<FDirectory, FJournal>(
    current: &Path,
    rollback: &Path,
    mut remove_directory: FDirectory,
    mut remove_journal: FJournal,
) -> Result<(), AppError>
where
    FDirectory: FnMut(&Path) -> io::Result<()>,
    FJournal: FnMut(&Path) -> io::Result<()>,
{
    let paths = sibling_paths_from_current(current)?;
    let current_name = file_name_string(current)?;
    let rollback_name = file_name_string(rollback)?;
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let mut journal = read_journal(&journal_path)?;
    if !matches!(
        journal.phase,
        TransactionPhase::Promoted | TransactionPhase::Retained | TransactionPhase::Committed
    ) || journal.current_name != current_name
        || journal.rollback_name != rollback_name
    {
        return Err(transaction_error(
            "Нельзя удалить резервную копию: запись не подтверждает завершённое обновление."
                .to_owned(),
        ));
    }
    let stage = paths.parent.join(&journal.stage_name);
    validate_transaction_paths(&stage, current, rollback, true)?;
    if !current.is_dir()
        || path_exists_or_link(&stage)?
        || (journal.phase != TransactionPhase::Committed && !rollback.is_dir())
    {
        return Err(transaction_error(
            "Текущая или резервная папка отсутствует; резервная копия сохранена.".to_owned(),
        ));
    }
    validate_staged_engine(current, None)?;
    if journal.phase != TransactionPhase::Committed {
        // Persist the irreversible boundary before removing even one old file.
        // If writing fails, the previous backup remains completely untouched.
        journal.phase = TransactionPhase::Committed;
        write_journal(&journal_path, &journal)?;
    }
    if path_exists_or_link(rollback)? {
        remove_directory(rollback).map_err(|error| {
            transaction_error(format!(
                "Не удалось удалить подтверждённую резервную копию {}: {error}. Новая версия сохранена; очистка будет повторена.",
                rollback.display()
            ))
        })?;
    }
    remove_journal(&journal_path).map_err(|error| {
        transaction_error(format!(
            "Резервная копия удалена, но не удалось удалить запись транзакции: {error}"
        ))
    })?;
    Ok(())
}

fn promote_engine_with_rename<F>(
    stage: &Path,
    current: &Path,
    rollback: &Path,
    mut rename: F,
) -> Result<(), AppError>
where
    F: FnMut(&Path, &Path) -> io::Result<()>,
{
    // Validation happens before touching current or creating transaction state.
    validate_staged_engine(stage, None)?;
    let paths = validate_transaction_paths(stage, current, rollback, false)?;
    let journal_path = paths.parent.join(JOURNAL_NAME);
    let journal_temp = paths.parent.join(JOURNAL_TEMP_NAME);
    if path_exists_or_link(&journal_path)? || path_exists_or_link(&journal_temp)? {
        return Err(transaction_error(
            "Уже существует незавершённая запись обновления. Сначала выполните восстановление."
                .to_owned(),
        ));
    }
    if !current.is_dir() {
        return Err(transaction_error(
            "Текущая папка движка отсутствует; обновление не начато.".to_owned(),
        ));
    }

    let mut journal = TransactionJournal {
        version: 1,
        stage_name: file_name_string(stage)?,
        current_name: file_name_string(current)?,
        rollback_name: file_name_string(rollback)?,
        phase: TransactionPhase::Prepared,
    };
    write_journal(&journal_path, &journal)?;

    journal.phase = TransactionPhase::MovingCurrentToRollback;
    write_journal(&journal_path, &journal)?;
    rename(current, rollback).map_err(|error| {
        transaction_error(format!("Не удалось сохранить текущий движок: {error}"))
    })?;
    journal.phase = TransactionPhase::CurrentMovedToRollback;
    write_journal(&journal_path, &journal)?;

    journal.phase = TransactionPhase::PromotingStage;
    write_journal(&journal_path, &journal)?;
    if let Err(promotion_error) = rename(stage, current) {
        journal.phase = TransactionPhase::RestoringRollback;
        if let Err(journal_error) = write_journal(&journal_path, &journal) {
            return Err(transaction_error(format!(
                "Не удалось установить обновление ({promotion_error}) и записать состояние для восстановления ({journal_error}). Предыдущая версия сохранена в {}.",
                rollback.display()
            )));
        }
        match rename(rollback, current) {
            Ok(()) => {
                journal.phase = TransactionPhase::RolledBack;
                let journal_result = write_journal(&journal_path, &journal);
                let recovery_note = journal_result
                    .err()
                    .map(|error| format!(" Не удалось обновить запись восстановления: {error}."))
                    .unwrap_or_default();
                return Err(transaction_error(format!(
                    "Не удалось установить новую версию: {promotion_error}. Предыдущая версия восстановлена.{recovery_note}"
                )));
            }
            Err(restore_error) => {
                return Err(transaction_error(format!(
                    "Не удалось установить новую версию ({promotion_error}) и автоматически вернуть предыдущую ({restore_error}). Предыдущая версия сохранена в {}.",
                    rollback.display()
                )));
            }
        }
    }
    journal.phase = TransactionPhase::Promoted;
    write_journal(&journal_path, &journal)
}

struct ValidatedPaths {
    parent: PathBuf,
}

fn validate_transaction_paths(
    stage: &Path,
    current: &Path,
    rollback: &Path,
    allow_stage_missing: bool,
) -> Result<ValidatedPaths, AppError> {
    let stage_parent = canonical_parent(stage)?;
    let current_parent = canonical_parent(current)?;
    let rollback_parent = canonical_parent(rollback)?;
    if stage_parent != current_parent || stage_parent != rollback_parent {
        return Err(path_error(
            "Подготовленная, текущая и резервная папки должны находиться в одной папке движка."
                .to_owned(),
        ));
    }
    let stage_name = file_name_string(stage)?;
    let current_name = file_name_string(current)?;
    let rollback_name = file_name_string(rollback)?;
    if !safe_child_name(&stage_name)
        || !safe_child_name(&current_name)
        || !safe_child_name(&rollback_name)
    {
        return Err(path_error(
            "Имена папок движка содержат недопустимые символы.".to_owned(),
        ));
    }
    if stage_name.eq_ignore_ascii_case(&current_name)
        || stage_name.eq_ignore_ascii_case(&rollback_name)
        || current_name.eq_ignore_ascii_case(&rollback_name)
    {
        return Err(path_error(
            "Пути подготовки, текущей версии и резервной копии должны быть разными.".to_owned(),
        ));
    }
    let canonical_stage = stage_parent.join(&stage_name);
    if allow_stage_missing && !path_exists_or_link(&canonical_stage)? {
        // A missing stage is expected after its promotion. The caller still
        // verifies journal and directory state before using it.
    } else if !allow_stage_missing
        && fs::canonicalize(stage).ok().as_deref() != Some(canonical_stage.as_path())
    {
        return Err(path_error(
            "Путь подготовки должен быть непосредственной папкой движка, без символических ссылок."
                .to_owned(),
        ));
    }
    for path in [current, rollback] {
        validate_optional_directory(&stage_parent.join(file_name_string(path)?))?;
    }
    if allow_stage_missing {
        validate_optional_directory(&canonical_stage)?;
    }
    Ok(ValidatedPaths {
        parent: stage_parent,
    })
}

fn sibling_paths_from_current(current: &Path) -> Result<ValidatedPaths, AppError> {
    Ok(ValidatedPaths {
        parent: canonical_parent(current)?,
    })
}

fn canonical_parent(path: &Path) -> Result<PathBuf, AppError> {
    let parent = path
        .parent()
        .ok_or_else(|| path_error("Путь движка должен указывать на дочернюю папку.".to_owned()))?;
    let name = path
        .file_name()
        .ok_or_else(|| path_error("В пути движка отсутствует имя папки.".to_owned()))?;
    if name.is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(path_error(
            "Путь движка содержит недопустимые компоненты.".to_owned(),
        ));
    }
    fs::canonicalize(parent)
        .map_err(|error| path_error(format!("Не удалось проверить папку движка: {error}")))
}

fn validate_optional_directory(path: &Path) -> Result<(), AppError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(path_error(format!(
                "Путь {} существует, но не является обычной папкой.",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(path_error(format!(
            "Не удалось проверить папку {}: {error}",
            path.display()
        ))),
    }
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn is_plain_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn path_exists_or_link(path: &Path) -> Result<bool, AppError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(path_error(format!(
            "Не удалось проверить путь {}: {error}",
            path.display()
        ))),
    }
}

fn file_name_string(path: &Path) -> Result<String, AppError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .map(str::to_owned)
        .ok_or_else(|| path_error("Имя папки движка имеет неподдерживаемый формат.".to_owned()))
}

fn read_journal(path: &Path) -> Result<TransactionJournal, AppError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(transaction_error(
                "Запись обновления должна быть обычным файлом.".to_owned(),
            ));
        }
        Ok(metadata) if metadata.len() > 16 * 1024 => {
            return Err(transaction_error(
                "Размер записи обновления превышает допустимый предел.".to_owned(),
            ));
        }
        Ok(_) => {}
        Err(error) => {
            return Err(transaction_error(format!(
                "Не удалось проверить запись обновления: {error}"
            )));
        }
    }
    let bytes = fs::read(path).map_err(|error| {
        transaction_error(format!("Не удалось прочитать запись обновления: {error}"))
    })?;
    if bytes.len() > 16 * 1024 {
        return Err(transaction_error(
            "Размер записи обновления превышает допустимый предел.".to_owned(),
        ));
    }
    let journal: TransactionJournal = serde_json::from_slice(&bytes)
        .map_err(|error| transaction_error(format!("Запись обновления повреждена: {error}")))?;
    if journal.version != 1
        || !safe_child_name(&journal.stage_name)
        || !safe_child_name(&journal.current_name)
        || !safe_child_name(&journal.rollback_name)
    {
        return Err(transaction_error(
            "Запись обновления содержит неподдерживаемые пути или версию.".to_owned(),
        ));
    }
    Ok(journal)
}

fn safe_child_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && !name
            .chars()
            .any(|character| matches!(character, '/' | '\\' | ':'))
        && !name.chars().any(char::is_control)
}

fn write_journal(path: &Path, journal: &TransactionJournal) -> Result<(), AppError> {
    let parent = path.parent().ok_or_else(|| {
        transaction_error("Не удалось определить папку записи обновления.".to_owned())
    })?;
    let temp = parent.join(JOURNAL_TEMP_NAME);
    if path_exists_or_link(&temp)? {
        return Err(transaction_error(
            "Временная запись обновления уже существует; автоматическая перезапись запрещена."
                .to_owned(),
        ));
    }
    let bytes = serde_json::to_vec(journal).map_err(|error| {
        transaction_error(format!("Не удалось подготовить запись обновления: {error}"))
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| {
            transaction_error(format!("Не удалось создать запись обновления: {error}"))
        })?;
    let result = (|| -> io::Result<()> {
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        return Err(transaction_error(format!(
            "Не удалось сохранить запись обновления: {error}"
        )));
    }
    Ok(())
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn update_error(code: &'static str, message: &'static str, detail: String) -> AppError {
    AppError::new(
        code,
        message,
        "Проверьте целостность файлов обновления и повторите попытку.",
    )
    .with_detail(detail)
}

fn path_error(detail: String) -> AppError {
    update_error(
        "update_path_invalid",
        "Не удалось безопасно проверить папки движка.",
        detail,
    )
}

fn transaction_error(detail: String) -> AppError {
    update_error(
        "update_transaction_failed",
        "Не удалось безопасно завершить обновление zapret.",
        detail,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!("zapret-update-test-{nonce}"));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn engine(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn valid_engine(&self, name: &str) -> PathBuf {
            let root = self.engine(name);
            fs::create_dir_all(root.join("bin")).unwrap();
            fs::create_dir_all(root.join("lists")).unwrap();
            fs::create_dir_all(root.join(".service")).unwrap();
            fs::write(root.join("bin/winws.exe"), b"placeholder").unwrap();
            fs::write(root.join("bin/WinDivert.dll"), b"placeholder").unwrap();
            fs::write(root.join("bin/WinDivert64.sys"), b"placeholder").unwrap();
            fs::write(root.join("service.bat"), b"data only; never executed").unwrap();
            fs::write(root.join("lists/list-general.txt"), b"example.org\n").unwrap();
            fs::write(root.join(".service/version.txt"), "1.10.3\n").unwrap();
            fs::write(
                root.join("general (ALT13).bat"),
                "@echo off\r\nstart \"zapret: %~n0\" /min \"%BIN%winws.exe\" --wf-tcp=80,443,%GameFilterTCP%\r\n",
            )
            .unwrap();
            root
        }

        fn marker(path: &Path, text: &str) {
            fs::create_dir_all(path).unwrap();
            fs::write(path.join("marker"), text).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn invalid_stage_leaves_current_untouched() {
        let fixture = Fixture::new();
        let stage = fixture.engine("stage");
        fs::create_dir(&stage).unwrap();
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");

        assert!(promote_engine(&stage, &current, &rollback).is_err());
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"old");
        assert!(!rollback.exists());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
    }

    #[test]
    fn first_install_rejects_invalid_stage_without_creating_current() {
        let fixture = Fixture::new();
        let stage = fixture.engine("stage");
        fs::create_dir(&stage).unwrap();
        let current = fixture.engine("current");
        assert!(promote_initial_engine(&stage, &current).is_err());
        assert!(!current.exists());
        assert!(stage.is_dir());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
    }

    #[test]
    fn first_install_promotes_and_finalizes_without_rollback() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        promote_initial_engine(&stage, &current).unwrap();
        assert!(current.join("bin/winws.exe").is_file());
        assert!(!stage.exists());
        assert!(fixture.engine(JOURNAL_NAME).is_file());
        finalize_initial_engine(&current).unwrap();
        assert!(!fixture.engine(JOURNAL_NAME).exists());
        assert!(!fixture.engine(".rollback-initial-reserved").exists());
    }

    #[test]
    fn failed_first_install_rename_preserves_validated_stage_for_retry() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        let result = promote_initial_engine_with_rename(&stage, &current, |_, _| {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected"))
        });
        assert!(result.is_err());
        assert!(!current.exists());
        assert!(stage.join("bin/winws.exe").is_file());
        assert!(initial_install_recovery_pending(&current).unwrap());
        assert!(recover_engine_update(&current).unwrap().is_some());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
        assert!(stage.join("bin/winws.exe").is_file());
    }

    #[test]
    fn interrupted_first_install_moves_promoted_engine_back_to_stage() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        promote_initial_engine(&stage, &current).unwrap();
        assert!(initial_install_recovery_pending(&current).unwrap());
        let recovered = recover_engine_update(&current).unwrap().unwrap();
        assert!(!current.exists());
        assert!(recovered.join("bin/winws.exe").is_file());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
    }

    #[test]
    fn failed_post_promotion_validation_restores_absent_current() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        promote_initial_engine(&stage, &current).unwrap();
        fs::remove_file(current.join("bin/winws.exe")).unwrap();
        assert!(finalize_initial_engine(&current).is_err());
        rollback_initial_engine(&current).unwrap();
        assert!(!current.exists());
        assert!(stage.is_dir());
        assert!(recover_engine_update(&current).unwrap().is_some());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
    }

    #[test]
    fn first_install_never_overwrites_existing_engine() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "keep");
        assert!(promote_initial_engine(&stage, &current).is_err());
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"keep");
        assert!(stage.join("bin/winws.exe").is_file());
    }

    #[test]
    fn promotion_keeps_previous_engine_in_rollback() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");

        promote_engine(&stage, &current, &rollback).unwrap();
        assert!(current.join("bin/winws.exe").is_file());
        assert_eq!(fs::read(rollback.join("marker")).unwrap(), b"old");
        assert!(!stage.exists());
        assert!(fixture.engine(JOURNAL_NAME).is_file());
    }

    #[test]
    fn failed_stage_promotion_restores_previous_engine() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        let mut failed_stage_move = false;

        let result = promote_engine_with_rename(&stage, &current, &rollback, |from, to| {
            if from == stage && to == current && !failed_stage_move {
                failed_stage_move = true;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected"));
            }
            fs::rename(from, to)
        });
        assert!(result.is_err());
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"old");
        assert!(!rollback.exists());
        assert!(stage.join("bin/winws.exe").is_file());
    }

    #[test]
    fn validation_requires_selected_bat_without_parsing_optional_commands() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        assert!(validate_staged_engine(&stage, Some("general (ALT10)")).is_err());
        fs::write(
            stage.join("general (ALT13).bat"),
            "@echo off\r\nrem future official strategy feature\r\n",
        )
        .unwrap();
        assert!(validate_staged_engine(&stage, Some("general (ALT13)")).is_ok());
    }

    #[test]
    fn first_install_accepts_release_without_runtime_user_lists() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        assert!(validate_staged_engine(&stage, None).is_ok());
        assert!(!stage.join("lists/list-general-user.txt").exists());
        assert!(!stage.join("lists/ipset-exclude-user.txt").exists());
    }

    #[test]
    fn committed_retained_release_survives_recovery_and_can_be_rolled_back() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.valid_engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        commit_engine_update_retaining_rollback(&current, &rollback).unwrap();

        assert_eq!(
            retained_engine_rollback(&current).unwrap(),
            Some(fs::canonicalize(&rollback).unwrap())
        );
        assert_eq!(recover_engine_update(&current).unwrap(), None);
        assert_eq!(fs::read(rollback.join("marker")).unwrap(), b"old");

        rollback_retained_engine(&current).unwrap();
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"old");
        assert_eq!(
            recover_engine_update(&current).unwrap_err().code,
            "update_runtime_recovery_pending"
        );
        finalize_retained_rollback(&current).unwrap();
        assert!(!stage.exists());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
    }

    #[test]
    fn failed_user_rollback_restart_can_restore_new_release() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.valid_engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        commit_engine_update_retaining_rollback(&current, &rollback).unwrap();
        rollback_retained_engine(&current).unwrap();

        undo_retained_rollback(&current).unwrap();
        assert!(current.join("bin/winws.exe").is_file());
        assert_eq!(fs::read(rollback.join("marker")).unwrap(), b"old");
        assert_eq!(
            retained_engine_rollback(&current).unwrap(),
            Some(fs::canonicalize(&rollback).unwrap())
        );
    }

    #[test]
    fn interrupted_user_rollback_rename_resumes_without_losing_either_release() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.valid_engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        commit_engine_update_retaining_rollback(&current, &rollback).unwrap();

        let journal_path = fixture.engine(JOURNAL_NAME);
        let mut journal = read_journal(&journal_path).unwrap();
        journal.phase = TransactionPhase::UserMovingPromotedToStage;
        write_journal(&journal_path, &journal).unwrap();
        fs::rename(&current, &stage).unwrap();

        resume_retained_rollback(&current).unwrap();
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"old");
        assert!(stage.join("bin/winws.exe").is_file());
        assert_eq!(
            read_journal(&journal_path).unwrap().phase,
            TransactionPhase::UserRolledBack
        );

        undo_retained_rollback(&current).unwrap();
        assert!(current.join("bin/winws.exe").is_file());
        assert_eq!(fs::read(rollback.join("marker")).unwrap(), b"old");
    }

    #[test]
    fn interrupted_undo_resumes_to_retained_state() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.valid_engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        commit_engine_update_retaining_rollback(&current, &rollback).unwrap();
        rollback_retained_engine(&current).unwrap();

        let journal_path = fixture.engine(JOURNAL_NAME);
        let mut journal = read_journal(&journal_path).unwrap();
        journal.phase = TransactionPhase::UndoingUserRollback;
        write_journal(&journal_path, &journal).unwrap();
        fs::rename(&current, &rollback).unwrap();

        assert_eq!(recover_engine_update(&current).unwrap(), None);
        assert!(current.join("bin/winws.exe").is_file());
        assert_eq!(fs::read(rollback.join("marker")).unwrap(), b"old");
        assert_eq!(
            read_journal(&journal_path).unwrap().phase,
            TransactionPhase::Retained
        );
    }

    #[test]
    fn partial_cleanup_of_superseded_release_never_undoes_user_rollback() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.valid_engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        commit_engine_update_retaining_rollback(&current, &rollback).unwrap();
        rollback_retained_engine(&current).unwrap();
        let journal_path = fixture.engine(JOURNAL_NAME);
        let mut journal = read_journal(&journal_path).unwrap();
        journal.phase = TransactionPhase::UserRollbackCommitted;
        write_journal(&journal_path, &journal).unwrap();
        fs::remove_file(stage.join("bin/winws.exe")).unwrap();

        assert!(user_rollback_committed(&current).unwrap());
        assert!(undo_retained_rollback(&current).is_err());
        assert_eq!(recover_engine_update(&current).unwrap(), None);
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"old");
        assert!(!stage.exists());
    }

    #[test]
    fn failed_user_rollback_commit_write_is_not_reported_as_cleanup_warning() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.valid_engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        commit_engine_update_retaining_rollback(&current, &rollback).unwrap();
        rollback_retained_engine(&current).unwrap();
        fs::write(fixture.engine(JOURNAL_TEMP_NAME), b"blocked journal").unwrap();

        assert!(finalize_retained_rollback(&current).is_err());
        assert!(!user_rollback_committed(&current).unwrap());
        assert!(stage.join("bin/winws.exe").is_file());
        assert_eq!(
            read_journal(&fixture.engine(JOURNAL_NAME)).unwrap().phase,
            TransactionPhase::UserRolledBack
        );
    }

    #[test]
    fn rollback_moves_new_engine_aside_and_restores_previous() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();

        rollback_engine(&current, &rollback).unwrap();
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"old");
        assert!(stage.join("bin/winws.exe").is_file());
        assert!(!rollback.exists());
    }

    #[test]
    fn recovery_rolls_back_interrupted_promotion_and_returns_stage() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();

        let journal_path = fixture.engine(JOURNAL_NAME);
        let mut journal = read_journal(&journal_path).unwrap();
        journal.phase = TransactionPhase::PromotingStage;
        write_journal(&journal_path, &journal).unwrap();
        let recovered_stage = recover_engine_update(&current).unwrap().unwrap();

        assert_eq!(
            fs::canonicalize(&recovered_stage).unwrap(),
            fs::canonicalize(&stage).unwrap()
        );
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"old");
        assert!(stage.join("bin/winws.exe").is_file());
        assert!(!rollback.exists());
        assert!(!journal_path.exists());
    }

    #[test]
    fn finalize_removes_only_the_retained_previous_engine() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();

        finalize_engine_update(&current, &rollback).unwrap();

        assert!(current.join("bin/winws.exe").is_file());
        assert!(!rollback.exists());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
    }

    #[test]
    fn partial_backup_cleanup_never_rolls_back_and_recovery_preserves_current() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        fs::write(current.join("remaining"), b"old remainder").unwrap();
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();

        let result = finalize_engine_update_with_cleanup(
            &current,
            &rollback,
            |path| {
                fs::remove_file(path.join("marker"))?;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected partial cleanup",
                ))
            },
            |path| fs::remove_file(path),
        );
        assert!(result.is_err());
        assert_eq!(
            read_journal(&fixture.engine(JOURNAL_NAME)).unwrap().phase,
            TransactionPhase::Committed
        );
        assert!(!rollback.join("marker").exists());
        assert!(rollback.join("remaining").exists());
        assert!(rollback_engine(&current, &rollback).is_err());
        assert!(current.join("bin/winws.exe").is_file());

        assert_eq!(recover_engine_update(&current).unwrap(), None);
        assert!(current.join("bin/winws.exe").is_file());
        assert!(!rollback.exists());
        assert!(!stage.exists());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
    }

    #[test]
    fn post_cleanup_journal_failure_retries_without_rollback() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();

        let result = finalize_engine_update_with_cleanup(
            &current,
            &rollback,
            |path| fs::remove_dir_all(path),
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected journal cleanup",
                ))
            },
        );
        assert!(result.is_err());
        assert!(!rollback.exists());
        assert_eq!(
            read_journal(&fixture.engine(JOURNAL_NAME)).unwrap().phase,
            TransactionPhase::Committed
        );
        assert!(rollback_engine(&current, &rollback).is_err());
        assert_eq!(recover_engine_update(&current).unwrap(), None);
        assert!(current.join("bin/winws.exe").is_file());
        assert!(!fixture.engine(JOURNAL_NAME).exists());
    }

    #[test]
    fn commit_write_failure_leaves_backup_untouched() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        fs::write(fixture.engine(JOURNAL_TEMP_NAME), b"busy temporary journal").unwrap();

        assert!(finalize_engine_update(&current, &rollback).is_err());
        assert_eq!(
            read_journal(&fixture.engine(JOURNAL_NAME)).unwrap().phase,
            TransactionPhase::Promoted
        );
        assert_eq!(fs::read(rollback.join("marker")).unwrap(), b"old");
        assert!(current.join("bin/winws.exe").is_file());
    }

    #[test]
    fn committed_cleanup_rejects_aliased_journal_names() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        let journal_path = fixture.engine(JOURNAL_NAME);
        let mut journal = read_journal(&journal_path).unwrap();
        journal.phase = TransactionPhase::Committed;
        journal.rollback_name = "CURRENT".into();
        write_journal(&journal_path, &journal).unwrap();

        assert!(recover_engine_update(&current).is_err());
        assert!(current.join("bin/winws.exe").is_file());
        assert_eq!(fs::read(rollback.join("marker")).unwrap(), b"old");
        for name in ["current.", "current ", "../current", "current:stream"] {
            assert!(!safe_child_name(name));
        }
    }

    #[test]
    fn promoted_update_with_rollback_blocks_automatic_recovery() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();

        let error = recover_engine_update(&current).unwrap_err();

        assert_eq!(error.code, "update_runtime_recovery_pending");
        assert!(current.join("bin/winws.exe").is_file());
        assert_eq!(fs::read(rollback.join("marker")).unwrap(), b"old");
        assert!(fixture.engine(JOURNAL_NAME).is_file());
    }

    #[test]
    fn promoted_update_without_rollback_clears_stale_journal() {
        let fixture = Fixture::new();
        let stage = fixture.valid_engine("stage");
        let current = fixture.engine("current");
        Fixture::marker(&current, "old");
        let rollback = fixture.engine("rollback");
        promote_engine(&stage, &current, &rollback).unwrap();
        fs::remove_dir_all(&rollback).unwrap();
        let journal_path = fixture.engine(JOURNAL_NAME);

        assert_eq!(recover_engine_update(&current).unwrap(), None);

        assert!(current.join("bin/winws.exe").is_file());
        assert!(!journal_path.exists());
    }
}
