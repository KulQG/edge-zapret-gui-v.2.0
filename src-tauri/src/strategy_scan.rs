//! Sequential tests of official strategies with a durable restoration marker.
//! This runs only in the elevated scan helper. Individual launches still pass
//! through the verified manual BAT runner and its owned-process receipt.

use crate::error::AppError;
use crate::manual_helper::{self, OwnedIdentity};
use crate::strategy_probe::{self, EndpointCategory, ProbeResult, ProbeStatus, ProbeVariant};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

const JOURNAL_FILE: &str = "strategy-scan.json";
const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
const MAX_STRATEGIES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ScanScope {
    Youtube,
    Discord,
    Both,
}

impl ScanScope {
    fn requires(self, category: EndpointCategory) -> bool {
        match self {
            Self::Youtube => category == EndpointCategory::YouTube,
            Self::Discord => category == EndpointCategory::Discord,
            Self::Both => matches!(
                category,
                EndpointCategory::YouTube | EndpointCategory::Discord
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScanRequest {
    pub operation_id: String,
    pub strategy_ids: Vec<String>,
    pub scope: ScanScope,
    pub fast_mode: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ScanVerdict {
    Passed,
    Failed,
    Incomplete,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanResult {
    pub strategy_id: String,
    pub display_name: String,
    pub verdict: ScanVerdict,
    pub checks: Vec<ProbeResult>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ScanPhase {
    Preparing,
    Testing,
    Restoring,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RestorationState {
    None,
    Pending,
    Restored,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanProgress {
    pub operation_id: String,
    pub sequence: u64,
    pub phase: ScanPhase,
    pub current_strategy_id: Option<String>,
    pub completed_strategies: usize,
    pub total_strategies: usize,
    pub results: Vec<ScanResult>,
    pub restoration: RestorationState,
    pub error: Option<AppError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanState {
    pub active: bool,
    pub progress: Option<ScanProgress>,
    pub recovery_pending: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalIdentity {
    pid: u32,
    creation_time_100ns: u64,
    strategy_id: String,
}

impl From<OwnedIdentity> for JournalIdentity {
    fn from(value: OwnedIdentity) -> Self {
        Self {
            pid: value.pid,
            creation_time_100ns: value.creation_time_100ns,
            strategy_id: value.strategy_id,
        }
    }
}

impl JournalIdentity {
    fn matches(&self, other: &OwnedIdentity) -> bool {
        self.pid == other.pid
            && self.creation_time_100ns == other.creation_time_100ns
            && self.strategy_id == other.strategy_id
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScanJournal {
    version: u8,
    operation_id: String,
    original: Option<JournalIdentity>,
    active_candidate_id: Option<String>,
    active_candidate: Option<JournalIdentity>,
}

fn scan_error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(
        code,
        message,
        "Проверьте состояние стратегии и повторите операцию.",
    )
}

fn journal_path() -> Result<PathBuf, AppError> {
    let current = crate::diagnostics::engine_dir().map_err(|detail| {
        scan_error("scan_engine_path", "Папка движка недоступна.").with_detail(detail)
    })?;
    let engine = current
        .parent()
        .ok_or_else(|| scan_error("scan_engine_path", "Путь движка неверен."))?;
    Ok(engine.join(JOURNAL_FILE))
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn read_journal() -> Result<Option<ScanJournal>, AppError> {
    let path = journal_path()?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(
                scan_error("scan_journal_read", "Не удалось проверить запись теста.")
                    .with_detail(error.to_string()),
            )
        }
    };
    crate::storage_security::verify_engine_storage()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(scan_error(
            "scan_journal_invalid",
            "Запись теста повреждена.",
        ));
    }
    let bytes = fs::read(&path).map_err(|error| {
        scan_error("scan_journal_read", "Не удалось прочитать запись теста.")
            .with_detail(error.to_string())
    })?;
    let journal: ScanJournal = serde_json::from_slice(&bytes)
        .map_err(|_| scan_error("scan_journal_invalid", "Запись теста повреждена."))?;
    if journal.version != 1 || journal.operation_id.is_empty() || journal.operation_id.len() > 128 {
        return Err(scan_error(
            "scan_journal_invalid",
            "Запись теста повреждена.",
        ));
    }
    Ok(Some(journal))
}

fn write_journal(journal: &ScanJournal) -> Result<(), AppError> {
    crate::storage_security::verify_engine_storage()?;
    let path = journal_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| scan_error("scan_journal_write", "Папка записи теста недоступна."))?;
    let temp = parent.join(format!(
        ".strategy-scan-{}.tmp",
        crate::service_helper::new_pipe_id()?
    ));
    let result = (|| {
        let bytes = serde_json::to_vec(journal).map_err(|_| {
            scan_error("scan_journal_write", "Не удалось подготовить запись теста.")
        })?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(scan_error(
                "scan_journal_write",
                "Запись теста слишком велика.",
            ));
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|error| {
                scan_error("scan_journal_write", "Не удалось создать запись теста.")
                    .with_detail(error.to_string())
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| {
                scan_error("scan_journal_write", "Не удалось сохранить запись теста.")
                    .with_detail(error.to_string())
            })?;
        drop(file);
        if unsafe {
            MoveFileExW(
                wide(&temp).as_ptr(),
                wide(&path).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(
                scan_error("scan_journal_write", "Не удалось завершить запись теста.")
                    .with_detail(std::io::Error::last_os_error().to_string()),
            );
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn remove_journal() -> Result<(), AppError> {
    let path = journal_path()?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(
            scan_error("scan_journal_remove", "Не удалось удалить запись теста.")
                .with_detail(error.to_string()),
        ),
    }
}

pub(crate) fn pending_recovery() -> Result<bool, AppError> {
    Ok(read_journal()?.is_some())
}

fn recorded_candidate_matches(journal: &ScanJournal, current: &OwnedIdentity) -> bool {
    journal
        .active_candidate
        .as_ref()
        .is_some_and(|value| value.matches(current))
}

fn restore(journal: &ScanJournal) -> Result<(), AppError> {
    let current = manual_helper::owned_identity()?;
    if let Some(original) = &journal.original {
        if current
            .as_ref()
            .is_some_and(|value| original.matches(value))
        {
            return remove_journal();
        }
    }
    if let Some(current) = current {
        if !recorded_candidate_matches(journal, &current) {
            return Err(scan_error(
                "scan_restore_conflict",
                "Обнаружена другая управляемая стратегия. Восстановление остановлено.",
            ));
        }
        manual_helper::stop()?;
    }
    if let Some(original) = &journal.original {
        manual_helper::start(&original.strategy_id)?;
        // Once the prior strategy has a new PID, persist that exact identity
        // before removing the marker. A cleanup failure can then be retried
        // without mistaking the restored process for an unknown candidate.
        let restored = manual_helper::owned_identity()?.ok_or_else(|| {
            scan_error(
                "scan_restore_lost",
                "Восстановленная стратегия не обнаружена.",
            )
        })?;
        let mut updated = journal.clone();
        updated.original = Some(restored.into());
        updated.active_candidate = None;
        updated.active_candidate_id = None;
        write_journal(&updated).map_err(|error| {
            scan_error(
                "scan_restore_journal",
                "Стратегия восстановлена, но запись завершения теста не сохранилась.",
            )
            .with_detail(error.to_string())
        })?;
    }
    remove_journal()
}

/// Requires elevation. Only this module's journal permits restoring a prior
/// managed strategy; a changed receipt is a conflict, never a stop target.
pub(crate) fn recover_pending(mut on_progress: impl FnMut(&ScanProgress)) -> Result<(), AppError> {
    let parent = journal_parent()?;
    let _update_lock = crate::engine_update::acquire_update_lock(&parent)?;
    let _lock = manual_helper::lock_operation()?;
    let Some(journal) = read_journal()? else {
        return Ok(());
    };
    let mut progress = ScanProgress {
        operation_id: journal.operation_id.clone(),
        sequence: 1,
        phase: ScanPhase::Restoring,
        current_strategy_id: None,
        completed_strategies: 0,
        total_strategies: 0,
        results: Vec::new(),
        restoration: RestorationState::Pending,
        error: None,
    };
    on_progress(&progress);
    let result = restore(&journal);
    progress.sequence += 1;
    progress.restoration = if result.is_ok() {
        RestorationState::Restored
    } else {
        RestorationState::Failed
    };
    progress.phase = if result.is_ok() {
        ScanPhase::Completed
    } else {
        ScanPhase::Failed
    };
    progress.error = result.as_ref().err().cloned();
    on_progress(&progress);
    result
}

fn is_alt_strategy(id: &str) -> bool {
    let Some(inner) = id.strip_suffix(')') else {
        return false;
    };
    let Some(index) = inner.rfind("ALT") else {
        return false;
    };
    let before = inner[..index].chars().last();
    let suffix = &inner[index + 3..];
    matches!(before, Some('(' | ' '))
        && (suffix.is_empty() || suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_request(request: &ScanRequest) -> Result<Vec<String>, AppError> {
    if request.operation_id.is_empty()
        || request.operation_id.len() > 128
        || !request
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || request.strategy_ids.is_empty()
        || request.strategy_ids.len() > MAX_STRATEGIES
    {
        return Err(scan_error(
            "scan_request_invalid",
            "Неверные параметры теста.",
        ));
    }
    let root = crate::diagnostics::engine_dir().map_err(|detail| {
        scan_error("scan_engine_path", "Папка движка недоступна.").with_detail(detail)
    })?;
    let found = crate::strategy::discover_strategies(&root)?;
    let mut selected = Vec::with_capacity(request.strategy_ids.len());
    for id in &request.strategy_ids {
        if selected.contains(id) {
            return Err(scan_error(
                "scan_request_invalid",
                "Стратегия выбрана повторно.",
            ));
        }
        let item = found
            .iter()
            .find(|item| item.summary.id == *id && item.summary.supported && is_alt_strategy(id))
            .ok_or_else(|| {
                scan_error("scan_strategy_invalid", "Выбранная стратегия недоступна.")
            })?;
        selected.push(item.summary.id.clone());
    }
    Ok(selected)
}

fn journal_parent() -> Result<PathBuf, AppError> {
    crate::storage_security::verify_engine_storage()?;
    journal_path()?
        .parent()
        .ok_or_else(|| scan_error("scan_engine_path", "Путь движка неверен."))?
        .canonicalize()
        .map_err(|error| {
            scan_error("scan_engine_path", "Папка движка недоступна.")
                .with_detail(error.to_string())
        })
}

/// Probe each address concurrently, with its three variants in order. This
/// bounds the number of simultaneous curl children to the number of addresses.
/// A fast-mode failure cancels in-flight probes and skips work not yet started.
fn probe_endpoints(
    scope: ScanScope,
    fast_mode: bool,
    is_cancelled: &(impl Fn() -> bool + Sync),
    on_result: impl FnMut(ProbeResult),
) -> Result<(), AppError> {
    probe_endpoints_with(
        scope,
        fast_mode,
        is_cancelled,
        on_result,
        &|endpoint, variant, cancelled| strategy_probe::probe_one(endpoint, variant, cancelled),
    )
}

fn probe_endpoints_with(
    scope: ScanScope,
    fast_mode: bool,
    is_cancelled: &(impl Fn() -> bool + Sync),
    mut on_result: impl FnMut(ProbeResult),
    probe: &(impl Fn(&'static strategy_probe::ProbeEndpoint, ProbeVariant, &dyn Fn() -> bool) -> ProbeResult
          + Sync),
) -> Result<(), AppError> {
    let fast_rejected = AtomicBool::new(false);
    thread::scope(|threads| {
        let (sender, receiver) = mpsc::channel();
        let mut workers = Vec::with_capacity(strategy_probe::ENDPOINTS.len());
        for endpoint in &strategy_probe::ENDPOINTS {
            let sender = sender.clone();
            let fast_rejected = &fast_rejected;
            workers.push(threads.spawn(move || {
                let required = scope.requires(endpoint.category);
                let reference = matches!(
                    endpoint.category,
                    EndpointCategory::Google | EndpointCategory::Cloudflare
                );
                for variant in ProbeVariant::ALL {
                    let check = if !required && !reference {
                        strategy_probe::skipped(endpoint, variant)
                    } else {
                        probe(endpoint, variant, &|| {
                            is_cancelled() || (fast_mode && fast_rejected.load(Ordering::SeqCst))
                        })
                    };
                    if fast_mode
                        && required
                        && check.status != ProbeStatus::Passed
                        && !is_cancelled()
                    {
                        fast_rejected.store(true, Ordering::SeqCst);
                    }
                    if sender.send(check).is_err() {
                        return;
                    }
                }
            }));
        }
        drop(sender);
        for result in receiver {
            on_result(result);
        }
        let mut panicked = false;
        for worker in workers {
            panicked |= worker.join().is_err();
        }
        if panicked {
            Err(scan_error(
                "scan_probe_worker",
                "Проверка адреса прервалась.",
            ))
        } else {
            Ok(())
        }
    })
}

/// Runs synchronously in the elevated helper. `is_cancelled` must be cheap and
/// may be called while a curl process is running. Restoration always runs.
pub(crate) fn run_scan(
    request: ScanRequest,
    mut on_progress: impl FnMut(&ScanProgress),
    is_cancelled: impl Fn() -> bool + Sync,
) -> Result<ScanProgress, AppError> {
    let parent = journal_parent()?;
    let _update_lock = crate::engine_update::acquire_update_lock(&parent)?;
    let _lock = manual_helper::lock_operation()?;
    if read_journal()?.is_some() {
        return Err(scan_error(
            "scan_recovery_pending",
            "Предыдущий тест требует восстановления.",
        ));
    }
    let selected = validate_request(&request)?;
    let original = manual_helper::owned_identity()?;
    let mut progress = ScanProgress {
        operation_id: request.operation_id.clone(),
        sequence: 0,
        phase: ScanPhase::Preparing,
        current_strategy_id: None,
        completed_strategies: 0,
        total_strategies: selected.len(),
        results: Vec::new(),
        restoration: RestorationState::Pending,
        error: None,
    };
    let mut emit = |progress: &mut ScanProgress| {
        progress.sequence += 1;
        on_progress(progress);
    };
    emit(&mut progress);
    let mut journal = ScanJournal {
        version: 1,
        operation_id: request.operation_id,
        original: original.map(Into::into),
        active_candidate_id: None,
        active_candidate: None,
    };
    // The marker is durable before stopping the user's previous session.
    write_journal(&journal)?;
    let work = (|| -> Result<(), AppError> {
        if journal.original.is_some() {
            manual_helper::stop()?;
        }
        for id in selected {
            if is_cancelled() {
                break;
            }
            journal.active_candidate_id = Some(id.clone());
            journal.active_candidate = None;
            write_journal(&journal)?;
            manual_helper::start(&id)?;
            journal.active_candidate = manual_helper::owned_identity()?.map(Into::into);
            if journal.active_candidate.is_none() {
                return Err(scan_error(
                    "scan_start_lost",
                    "Запущенная стратегия не обнаружена.",
                ));
            }
            write_journal(&journal)?;
            progress.phase = ScanPhase::Testing;
            progress.current_strategy_id = Some(id.clone());
            let result = ScanResult {
                strategy_id: id.clone(),
                display_name: id,
                verdict: ScanVerdict::Incomplete,
                checks: Vec::new(),
            };
            progress.results.push(result);
            emit(&mut progress);
            let mut required_failed = false;
            let mut required_unsupported = false;
            probe_endpoints(request.scope, request.fast_mode, &is_cancelled, |check| {
                if request.scope.requires(check.category) && check.status != ProbeStatus::Passed {
                    required_failed = true;
                    required_unsupported |= check.status == ProbeStatus::Unsupported;
                }
                progress.results.last_mut().unwrap().checks.push(check);
                emit(&mut progress);
            })?;
            progress.results.last_mut().unwrap().verdict = if is_cancelled() {
                ScanVerdict::Incomplete
            } else if required_unsupported
                && progress
                    .results
                    .last()
                    .unwrap()
                    .checks
                    .iter()
                    .filter(|check| request.scope.requires(check.category))
                    .all(|check| check.status != ProbeStatus::Failed)
            {
                ScanVerdict::Unsupported
            } else if required_failed {
                ScanVerdict::Failed
            } else {
                ScanVerdict::Passed
            };
            manual_helper::stop()?;
            journal.active_candidate = None;
            journal.active_candidate_id = None;
            write_journal(&journal)?;
            progress.completed_strategies += 1;
            progress.current_strategy_id = None;
            emit(&mut progress);
        }
        Ok(())
    })();
    progress.phase = ScanPhase::Restoring;
    progress.current_strategy_id = None;
    emit(&mut progress);
    let restoration = restore(&journal);
    progress.restoration = if restoration.is_ok() {
        RestorationState::Restored
    } else {
        RestorationState::Failed
    };
    progress.error = work.err().or_else(|| restoration.err());
    progress.phase = if progress.error.is_some() {
        ScanPhase::Failed
    } else if is_cancelled() {
        ScanPhase::Cancelled
    } else {
        ScanPhase::Completed
    };
    emit(&mut progress);
    Ok(progress)
}

/// Checks the currently running app-owned strategy without changing its
/// process, window, selected strategy, or durable scan journal.
pub(crate) fn check_current(
    operation_id: String,
    scope: ScanScope,
    is_cancelled: impl Fn() -> bool + Sync,
    mut on_progress: impl FnMut(&ScanProgress),
) -> Result<ScanResult, AppError> {
    if operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(scan_error(
            "scan_request_invalid",
            "Неверные параметры теста.",
        ));
    }
    if pending_recovery()? {
        return Err(scan_error(
            "scan_recovery_pending",
            "Предыдущий тест требует восстановления.",
        ));
    }
    let owned = manual_helper::owned_identity()?.ok_or_else(|| {
        scan_error(
            "scan_current_missing",
            "Управляемая стратегия сейчас не запущена.",
        )
    })?;
    let id = owned.strategy_id.clone();
    let mut progress = ScanProgress {
        operation_id,
        sequence: 0,
        phase: ScanPhase::Testing,
        current_strategy_id: Some(id.clone()),
        completed_strategies: 0,
        total_strategies: 1,
        results: vec![ScanResult {
            strategy_id: id.clone(),
            display_name: id,
            verdict: ScanVerdict::Incomplete,
            checks: Vec::new(),
        }],
        restoration: RestorationState::None,
        error: None,
    };
    let mut required_failed = false;
    let mut required_unsupported = false;
    progress.sequence += 1;
    on_progress(&progress);
    probe_endpoints(scope, false, &is_cancelled, |check| {
        if scope.requires(check.category) && check.status != ProbeStatus::Passed {
            required_failed = true;
            required_unsupported |= check.status == ProbeStatus::Unsupported;
        }
        progress.results[0].checks.push(check);
        progress.sequence += 1;
        on_progress(&progress);
    })?;
    let same_process = manual_helper::exact_owned_matches(&owned)?;
    progress.results[0].verdict = if is_cancelled() || !same_process {
        ScanVerdict::Incomplete
    } else if required_unsupported
        && progress.results[0]
            .checks
            .iter()
            .filter(|check| scope.requires(check.category))
            .all(|check| check.status != ProbeStatus::Failed)
    {
        ScanVerdict::Unsupported
    } else if required_failed {
        ScanVerdict::Failed
    } else {
        ScanVerdict::Passed
    };
    progress.completed_strategies = 1;
    progress.current_strategy_id = None;
    progress.phase = if is_cancelled() {
        ScanPhase::Cancelled
    } else if !same_process {
        progress.error = Some(scan_error(
            "scan_current_changed",
            "Запущенная стратегия изменилась во время проверки.",
        ));
        ScanPhase::Failed
    } else {
        ScanPhase::Completed
    };
    progress.sequence += 1;
    on_progress(&progress);
    Ok(progress.results.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn addresses_run_concurrently_and_fast_failure_skips_remaining_checks() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let mut results = Vec::new();
        probe_endpoints_with(
            ScanScope::Both,
            false,
            &|| false,
            |result| results.push(result),
            &|endpoint, variant, _| {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(10));
                active.fetch_sub(1, Ordering::SeqCst);
                let mut result = strategy_probe::skipped(endpoint, variant);
                result.status = ProbeStatus::Passed;
                result
            },
        )
        .unwrap();
        assert_eq!(results.len(), strategy_probe::ENDPOINTS.len() * 3);
        assert!(peak.load(Ordering::SeqCst) > 1);

        results.clear();
        probe_endpoints_with(
            ScanScope::Both,
            true,
            &|| false,
            |result| results.push(result),
            &|endpoint, variant, cancelled| {
                let mut result = strategy_probe::skipped(endpoint, variant);
                if endpoint.key == "DiscordMain" && variant == ProbeVariant::Http11 {
                    result.status = ProbeStatus::Failed;
                } else if !cancelled() {
                    thread::sleep(Duration::from_millis(10));
                    result.status = if cancelled() {
                        ProbeStatus::Skipped
                    } else {
                        ProbeStatus::Passed
                    };
                }
                result
            },
        )
        .unwrap();
        assert_eq!(results.len(), strategy_probe::ENDPOINTS.len() * 3);
        assert!(results
            .iter()
            .any(|result| result.status == ProbeStatus::Failed));
        assert!(results
            .iter()
            .any(|result| result.status == ProbeStatus::Skipped));
    }

    #[test]
    fn alt_selection_rejects_non_alt_official_batches() {
        assert!(is_alt_strategy("general (ALT)"));
        assert!(is_alt_strategy("general (ALT13)"));
        assert!(is_alt_strategy("general (FAKE TLS AUTO ALT2)"));
        assert!(is_alt_strategy("general (SIMPLE FAKE ALT)"));
        assert!(!is_alt_strategy("general"));
        assert!(!is_alt_strategy("general (EXP)"));
        assert!(!is_alt_strategy("general (FAKE TLS AUTO)"));
        assert!(!is_alt_strategy("general (NOTALT2)"));
    }

    #[test]
    fn scope_counts_only_selected_service_for_verdict() {
        assert!(ScanScope::Youtube.requires(EndpointCategory::YouTube));
        assert!(!ScanScope::Youtube.requires(EndpointCategory::Discord));
        assert!(!ScanScope::Youtube.requires(EndpointCategory::Google));
        assert!(ScanScope::Both.requires(EndpointCategory::Discord));
        assert!(ScanScope::Both.requires(EndpointCategory::YouTube));
        assert!(!ScanScope::Both.requires(EndpointCategory::Cloudflare));
    }

    #[test]
    fn recovery_never_stops_a_process_from_strategy_name_alone() {
        let current = OwnedIdentity {
            pid: 101,
            creation_time_100ns: 987_654,
            strategy_id: "general (ALT2)".into(),
        };
        let mut journal = ScanJournal {
            version: 1,
            operation_id: "test".into(),
            original: None,
            active_candidate_id: Some(current.strategy_id.clone()),
            active_candidate: None,
        };
        assert!(!recorded_candidate_matches(&journal, &current));
        journal.active_candidate = Some(current.clone().into());
        assert!(recorded_candidate_matches(&journal, &current));
        journal
            .active_candidate
            .as_mut()
            .unwrap()
            .creation_time_100ns += 1;
        assert!(!recorded_candidate_matches(&journal, &current));
    }
}
