//! Discover official top-level strategy BAT files without interpreting their contents.
//!
//! The caller must supply a verified managed release root. Strategy IDs are
//! filenames without the `.bat` extension, never paths or shell commands.

use crate::error::AppError;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_STRATEGY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategySummary {
    pub id: String,
    pub display_name: String,
    pub source_file: String,
    /// `unknown` means the release has no readable `.service/version.txt`.
    pub release: String,
    pub supported: bool,
    pub unsupported_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub strategy_id: String,
    /// Canonical official BAT path. The BAT runner uses this field.
    pub batch_path: PathBuf,
    /// Canonical managed winws path used to identify the BAT's child process.
    pub executable_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct DiscoveredStrategy {
    pub summary: StrategySummary,
    pub launch_plan: Option<LaunchPlan>,
}

/// Enumerate top-level `general*.bat` files from a verified official release.
///
/// A candidate is checked for a safe filename, regular file, canonical
/// containment, and a static `bin/winws.exe`. Its BAT content and optional
/// release features are intentionally left to the official BAT.
pub fn discover_strategies(engine_root: &Path) -> Result<Vec<DiscoveredStrategy>, AppError> {
    let root = canonical_root(engine_root)?;
    let release = release_label(&root);
    let entries = fs::read_dir(&root).map_err(|error| {
        AppError::diagnostics().with_detail(format!("Не удалось прочитать стратегии: {error}"))
    })?;

    let mut paths = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| AppError::diagnostics().with_detail(error.to_string()))?;
        let path = entry.path();
        let Some(filename) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if is_general_bat_name(filename) {
            paths.push(path);
        }
    }
    paths.sort_by_key(|path| {
        path.file_name()
            .map(|value| value.to_string_lossy().to_lowercase())
    });

    let mut found = Vec::with_capacity(paths.len());
    for path in paths {
        let filename = path.file_name().and_then(|value| value.to_str()).unwrap();
        let id = filename[..filename.len() - 4].to_string();
        let mut summary = StrategySummary {
            id: id.clone(),
            display_name: id.clone(),
            source_file: filename.to_string(),
            release: release.clone(),
            supported: false,
            unsupported_reason: None,
        };
        let launch_plan = match build_plan(&root, &path, &id) {
            Ok(plan) => {
                summary.supported = true;
                Some(plan)
            }
            Err(reason) => {
                summary.unsupported_reason = Some(reason);
                None
            }
        };
        found.push(DiscoveredStrategy {
            summary,
            launch_plan,
        });
    }
    Ok(found)
}

fn canonical_root(engine_root: &Path) -> Result<PathBuf, AppError> {
    let metadata = fs::symlink_metadata(engine_root).map_err(|error| {
        AppError::diagnostics().with_detail(format!("Не удалось проверить папку движка: {error}"))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AppError::diagnostics()
            .with_detail("Папка движка должна быть обычным каталогом.".into()));
    }
    fs::canonicalize(engine_root).map_err(|error| {
        AppError::diagnostics().with_detail(format!("Не удалось проверить папку движка: {error}"))
    })
}

fn release_label(root: &Path) -> String {
    let Ok(value) = fs::read_to_string(root.join(".service").join("version.txt")) else {
        return "unknown".to_string();
    };
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        "unknown".to_string()
    } else {
        value.to_string()
    }
}

fn is_general_bat_name(filename: &str) -> bool {
    filename.len() >= 11
        && filename.to_ascii_lowercase().starts_with("general")
        && filename.to_ascii_lowercase().ends_with(".bat")
}

fn valid_strategy_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-' | b'.' | b'(' | b')')
        })
}

fn validate_batch_file(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "Имя стратегии недоступно.".to_string())?;
    let id = filename
        .get(..filename.len().saturating_sub(4))
        .ok_or_else(|| "Имя стратегии недоступно.".to_string())?;
    if !is_general_bat_name(filename) || !valid_strategy_id(id) || path.parent() != Some(root) {
        return Err("Имя стратегии содержит недопустимые символы.".into());
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "Не удалось открыть файл стратегии.".to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Стратегия должна быть обычным BAT-файлом.".into());
    }
    if metadata.len() == 0 || metadata.len() > MAX_STRATEGY_BYTES {
        return Err("Размер файла стратегии недопустим.".into());
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| "Не удалось проверить путь стратегии.".to_string())?;
    if canonical.parent() != Some(root) || !canonical.is_file() {
        return Err("Путь стратегии выходит за пределы движка.".into());
    }
    Ok(canonical)
}

fn build_plan(root: &Path, path: &Path, id: &str) -> Result<LaunchPlan, String> {
    let batch_path = validate_batch_file(root, path)?;
    let bin_path = root.join("bin");
    let bin_metadata = fs::symlink_metadata(&bin_path)
        .map_err(|_| "В движке отсутствует папка bin.".to_string())?;
    if !bin_metadata.is_dir() || bin_metadata.file_type().is_symlink() {
        return Err("Папка bin должна быть обычным каталогом.".into());
    }
    let bin =
        fs::canonicalize(&bin_path).map_err(|_| "Не удалось проверить папку bin.".to_string())?;
    if bin.parent() != Some(root) {
        return Err("Папка bin выходит за пределы движка.".into());
    }
    let executable_path = bin.join("winws.exe");
    let executable_metadata = fs::symlink_metadata(&executable_path)
        .map_err(|_| "В папке bin отсутствует winws.exe.".to_string())?;
    if !executable_metadata.is_file() || executable_metadata.file_type().is_symlink() {
        return Err("winws.exe должен быть обычным файлом.".into());
    }
    let executable_path = fs::canonicalize(&executable_path)
        .map_err(|_| "Не удалось проверить winws.exe.".to_string())?;
    if executable_path.parent() != Some(bin.as_path()) {
        return Err("Путь winws.exe выходит за пределы папки bin.".into());
    }
    Ok(LaunchPlan {
        strategy_id: id.to_string(),
        batch_path,
        executable_path,
    })
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
            let root = std::env::temp_dir().join(format!("zapret-strategy-test-{nonce}"));
            fs::create_dir_all(root.join("bin")).unwrap();
            fs::create_dir_all(root.join(".service")).unwrap();
            fs::write(root.join("bin/winws.exe"), b"placeholder").unwrap();
            fs::write(root.join(".service/version.txt"), b"2.0.0").unwrap();
            Self(root)
        }
        fn add_strategy(&self, name: &str, content: &[u8]) {
            fs::write(self.0.join(name), content).unwrap();
        }
        fn discover(&self) -> Vec<DiscoveredStrategy> {
            discover_strategies(&self.0).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn discovers_new_release_and_official_bat_without_parsing() {
        let fixture = Fixture::new();
        fixture.add_strategy(
            "general (FAKE TLS AUTO ALT2).bat",
            b"@echo off\r\ncall service.bat load_user_lists\r\nstart ...",
        );
        let found = fixture.discover();
        assert_eq!(found.len(), 1);
        assert!(found[0].summary.supported);
        assert_eq!(found[0].summary.release, "2.0.0");
        let plan = found[0].launch_plan.as_ref().unwrap();
        assert_eq!(plan.strategy_id, "general (FAKE TLS AUTO ALT2)");
        assert_eq!(
            plan.batch_path.parent(),
            Some(fs::canonicalize(&fixture.0).unwrap().as_path())
        );
    }

    #[test]
    fn runtime_generated_files_are_not_required() {
        let fixture = Fixture::new();
        // BAT encoding is the official script's concern, not a UTF-8 parser's.
        fixture.add_strategy(
            "general.bat",
            b"\xff\xfe\r\ncall service.bat load_user_lists",
        );
        assert!(fixture.discover()[0].summary.supported);
    }

    #[test]
    fn rejects_path_like_ids_and_bad_candidates() {
        let fixture = Fixture::new();
        fixture.add_strategy("general good.bat", b"echo ok");
        fixture.add_strategy("general&bad.bat", b"echo bad");
        fixture.add_strategy("general empty.bat", b"");
        fixture.add_strategy("service.bat", b"echo unrelated");
        let found = fixture.discover();
        assert_eq!(found.len(), 3);
        assert_eq!(
            found.iter().filter(|entry| entry.summary.supported).count(),
            1
        );
        let valid = found
            .iter()
            .find(|entry| entry.summary.id == "general good")
            .unwrap();
        assert_eq!(
            valid.launch_plan.as_ref().unwrap().batch_path,
            fs::canonicalize(fixture.0.join("general good.bat")).unwrap()
        );
    }

    #[test]
    fn rejects_oversized_strategy_and_missing_winws() {
        let fixture = Fixture::new();
        fixture.add_strategy("general.bat", &vec![b'x'; MAX_STRATEGY_BYTES as usize + 1]);
        assert!(!fixture.discover()[0].summary.supported);
        fixture.add_strategy("general.bat", b"echo ok");
        fs::remove_file(fixture.0.join("bin/winws.exe")).unwrap();
        assert!(!fixture.discover()[0].summary.supported);
    }
}
