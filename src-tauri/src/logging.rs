use crate::config::DataPaths;
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const MAX_ROTATED_FILES: usize = 4;
static LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

/// Messages come from this catalog, so routine logs cannot contain passwords,
/// browser URLs, arbitrary command arguments, or private user paths.
#[derive(Debug, Clone, Copy)]
pub enum LogCode {
    DiagnosticsRead,
    ConfigSaved,
    AppearanceCleanupFailed,
}

impl LogCode {
    fn parts(self) -> (&'static str, &'static str) {
        match self {
            Self::DiagnosticsRead => ("diagnostics_read", "Диагностика обновлена."),
            Self::ConfigSaved => ("config_saved", "Настройки сохранены."),
            Self::AppearanceCleanupFailed => (
                "appearance_cleanup_failed",
                "Оформление сохранено; часть неиспользуемых локальных копий изображений пока не удалена.",
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogEntry {
    pub timestamp_ms: u64,
    pub level: LogLevel,
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub detail: Option<String>,
}

impl LogEntry {
    fn new(level: LogLevel, code: LogCode) -> Self {
        let (code, message) = code.parts();
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            timestamp_ms,
            level,
            code: code.to_owned(),
            message: message.to_owned(),
            detail: None,
        }
    }
}

/// Writes bounded, structured progress from the fixed engine-update workflow.
/// Download byte ticks are filtered by the caller to keep the journal concise.
pub fn append_update_progress(
    paths: &DataPaths,
    retention_days: u16,
    progress: &crate::engine_update::EngineUpdateProgress,
) -> Result<(), AppError> {
    if !(1..=365).contains(&retention_days) {
        return Err(AppError::log_invalid());
    }
    let _guard = LOG_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| AppError::log_io())?;
    fs::create_dir_all(&paths.logs_dir).map_err(|_| AppError::log_io())?;
    prune_old_logs(&paths.logs_dir, retention_days)?;
    let (stage_code, stage_label) = match progress.stage {
        crate::engine_update::UpdateStage::Download => ("download", "Скачивание обновления"),
        crate::engine_update::UpdateStage::Validate => ("validate", "Проверка файлов"),
        crate::engine_update::UpdateStage::StopService => {
            ("stop_service", "Остановка службы zapret")
        }
        crate::engine_update::UpdateStage::StopManual => ("stop_manual", "Завершение winws.exe"),
        crate::engine_update::UpdateStage::StopWinDivert => {
            ("check_windivert", "Проверка WinDivert")
        }
        crate::engine_update::UpdateStage::Replace => ("replace", "Замена файлов"),
        crate::engine_update::UpdateStage::Restore => ("restore", "Восстановление режима"),
        crate::engine_update::UpdateStage::Complete => ("complete", "Готово"),
    };
    let (state_code, state_label, level) = match progress.state {
        crate::engine_update::UpdateProgressState::Started => ("started", "начато", LogLevel::Info),
        crate::engine_update::UpdateProgressState::Completed => {
            ("completed", "завершено", LogLevel::Info)
        }
        crate::engine_update::UpdateProgressState::Failed => ("failed", "ошибка", LogLevel::Error),
    };
    let mut entry = LogEntry::new(level, LogCode::DiagnosticsRead);
    entry.code = format!("engine_update_{stage_code}_{state_code}");
    entry.message = format!("Обновление: {stage_label} — {state_label}.");
    entry.detail = Some(bounded_text(
        progress.detail.as_deref().unwrap_or(&progress.message),
        4096,
    ));
    let mut bytes = serde_json::to_vec(&entry).map_err(|_| AppError::log_invalid())?;
    bytes.push(b'\n');
    let current = paths.logs_dir.join("app.jsonl");
    let current_size = match fs::metadata(&current) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(AppError::log_io()),
    };
    if current_size.saturating_add(bytes.len() as u64) > MAX_LOG_BYTES {
        rotate(&paths.logs_dir)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(current)
        .map_err(|_| AppError::log_io())?;
    file.write_all(&bytes).map_err(|_| AppError::log_io())?;
    file.flush().map_err(|_| AppError::log_io())?;
    Ok(())
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    let mut output = String::with_capacity(value.len().min(max_bytes));
    for character in value.chars() {
        if output.len() + character.len_utf8() > max_bytes {
            break;
        }
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        } else {
            output.push(' ');
        }
    }
    output
}

/// Appends one catalog event. Retention is both age-limited and size-limited.
pub fn append_event(
    paths: &DataPaths,
    retention_days: u16,
    level: LogLevel,
    code: LogCode,
) -> Result<(), AppError> {
    if !(1..=365).contains(&retention_days) {
        return Err(AppError::log_invalid());
    }
    let _guard = LOG_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| AppError::log_io())?;
    fs::create_dir_all(&paths.logs_dir).map_err(|_| AppError::log_io())?;
    prune_old_logs(&paths.logs_dir, retention_days)?;
    let entry = LogEntry::new(level, code);
    let mut bytes = serde_json::to_vec(&entry).map_err(|_| AppError::log_invalid())?;
    bytes.push(b'\n');
    let current = paths.logs_dir.join("app.jsonl");
    let current_size = match fs::metadata(&current) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(AppError::log_io()),
    };
    if current_size + bytes.len() as u64 > MAX_LOG_BYTES {
        rotate(&paths.logs_dir)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(current)
        .map_err(|_| AppError::log_io())?;
    file.write_all(&bytes).map_err(|_| AppError::log_io())?;
    file.flush().map_err(|_| AppError::log_io())?;
    Ok(())
}

fn rotate(dir: &Path) -> Result<(), AppError> {
    let oldest = dir.join(format!("app.{MAX_ROTATED_FILES}.jsonl"));
    if oldest.exists() {
        fs::remove_file(oldest).map_err(|_| AppError::log_io())?;
    }
    for index in (1..MAX_ROTATED_FILES).rev() {
        let from = dir.join(format!("app.{index}.jsonl"));
        if from.exists() {
            fs::rename(from, dir.join(format!("app.{}.jsonl", index + 1)))
                .map_err(|_| AppError::log_io())?;
        }
    }
    let current = dir.join("app.jsonl");
    if current.exists() {
        fs::rename(current, dir.join("app.1.jsonl")).map_err(|_| AppError::log_io())?;
    }
    Ok(())
}

fn prune_old_logs(dir: &Path, retention_days: u16) -> Result<(), AppError> {
    let age = Duration::from_secs(u64::from(retention_days) * 24 * 60 * 60);
    let now = SystemTime::now();
    for name in (0..=MAX_ROTATED_FILES).map(|index| {
        if index == 0 {
            "app.jsonl".to_owned()
        } else {
            format!("app.{index}.jsonl")
        }
    }) {
        let path = dir.join(name);
        match fs::metadata(&path) {
            Ok(metadata) => {
                let modified = metadata.modified().map_err(|_| AppError::log_io())?;
                if now.duration_since(modified).unwrap_or_default() > age {
                    fs::remove_file(path).map_err(|_| AppError::log_io())?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AppError::log_io()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn records_only_catalog_messages() {
        let base = std::env::temp_dir().join(format!(
            "zapret-gui-log-test-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&base).unwrap();
        let paths = DataPaths::from_local_appdata(&base).unwrap();
        append_event(&paths, 30, LogLevel::Info, LogCode::ConfigSaved).unwrap();
        let content = fs::read_to_string(paths.logs_dir.join("app.jsonl")).unwrap();
        let entry: LogEntry = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(entry.code, "config_saved");
        fs::remove_dir_all(base).unwrap();
    }
}
