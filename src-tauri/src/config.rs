use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const CONFIG_SCHEMA_VERSION: u32 = 2;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppConfig {
    pub schema_version: u32,
    pub selected_strategy: Option<String>,
    pub log_retention_days: u16,
    pub appearance: AppearanceSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum BackgroundFit {
    #[default]
    Cover,
    Contain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppearanceSettings {
    pub background_asset: Option<String>,
    pub mascot_asset: Option<String>,
    pub background_opacity: u8,
    pub background_blur: u8,
    pub background_position_x: u8,
    pub background_position_y: u8,
    pub background_fit: BackgroundFit,
    #[serde(default = "default_background_scale")]
    pub background_scale: u16,
    pub mascot_scale: u16,
    pub mascot_position_x: u8,
    pub mascot_position_y: u8,
    pub mascot_opacity: u8,
    pub dark_overlay: u8,
}

fn default_background_scale() -> u16 {
    100
}

impl Default for AppearanceSettings {
    fn default() -> Self {
        Self {
            background_asset: None,
            mascot_asset: None,
            background_opacity: 85,
            background_blur: 0,
            background_position_x: 50,
            background_position_y: 100,
            background_fit: BackgroundFit::Contain,
            background_scale: default_background_scale(),
            mascot_scale: 100,
            mascot_position_x: 50,
            mascot_position_y: 50,
            mascot_opacity: 100,
            dark_overlay: 10,
        }
    }
}

impl AppearanceSettings {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.background_opacity > 100
            || self.background_blur > 30
            || self.background_position_x > 100
            || self.background_position_y > 100
            || !(50..=200).contains(&self.background_scale)
            || !(50..=175).contains(&self.mascot_scale)
            || self.mascot_position_x > 100
            || self.mascot_position_y > 100
            || self.mascot_opacity > 100
            || self.dark_overlay > 90
            || self
                .background_asset
                .as_deref()
                .is_some_and(|id| !validate_asset_id(id))
            || self
                .mascot_asset
                .as_deref()
                .is_some_and(|id| !validate_asset_id(id))
        {
            return Err(AppError::config_invalid());
        }
        Ok(())
    }
}

/// Asset references are content hashes with an approved extension, never paths.
pub fn validate_asset_id(id: &str) -> bool {
    let Some((hash, extension)) = id.rsplit_once('.') else {
        return false;
    };
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && matches!(extension, "png" | "jpg" | "webp")
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            selected_strategy: None,
            log_retention_days: 30,
            appearance: AppearanceSettings::default(),
        }
    }
}

impl AppConfig {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(AppError::config_unsupported());
        }
        if !(1..=365).contains(&self.log_retention_days) {
            return Err(AppError::config_invalid());
        }
        if let Some(name) = &self.selected_strategy {
            if !valid_strategy_name(name) {
                return Err(AppError::config_invalid());
            }
        }
        self.appearance.validate()
    }
}

fn valid_strategy_name(name: &str) -> bool {
    let bytes = name.len();
    bytes > 0
        && bytes <= 128
        && name != "."
        && name != ".."
        && !name.ends_with(' ')
        && !name.ends_with('.')
        && !name.starts_with(' ')
        && !name.chars().any(|ch| {
            ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
}

/// Every per-user path is derived from LOCALAPPDATA, never accepted from the frontend.
#[derive(Debug, Clone)]
pub struct DataPaths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub legacy_config_file: PathBuf,
    pub logs_dir: PathBuf,
    pub appearance_dir: PathBuf,
}

impl DataPaths {
    pub fn discover() -> Result<Self, AppError> {
        let base = crate::diagnostics::local_app_data().map_err(|_| AppError::data_directory())?;
        Self::from_local_appdata(&base)
    }

    pub fn from_local_appdata(base: &Path) -> Result<Self, AppError> {
        if !base.is_absolute() {
            return Err(AppError::data_directory());
        }
        let root = base.join("ZapretGui");
        let config_dir = root.join("config");
        Ok(Self {
            config_file: config_dir.join("v2.json"),
            legacy_config_file: config_dir.join("v1.json"),
            logs_dir: root.join("logs"),
            appearance_dir: root.join("appearance"),
            config_dir,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigV0 {
    schema_version: u32,
    selected_strategy: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigV1 {
    schema_version: u32,
    selected_strategy: Option<String>,
    log_retention_days: u16,
}

/// Migrates only the explicitly recognized internal v0/v1 schemas. Old Electron
/// localStorage is intentionally not interpreted as an application config.
pub fn decode_config(data: &[u8]) -> Result<AppConfig, AppError> {
    if data.len() as u64 > MAX_CONFIG_BYTES {
        return Err(AppError::config_invalid());
    }
    let value: serde_json::Value =
        serde_json::from_slice(data).map_err(|_| AppError::config_invalid())?;
    let version = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(AppError::config_invalid)?;
    let config = match version {
        0 => {
            let old: ConfigV0 =
                serde_json::from_value(value).map_err(|_| AppError::config_invalid())?;
            if old.schema_version != 0 {
                return Err(AppError::config_invalid());
            }
            AppConfig {
                selected_strategy: old.selected_strategy,
                ..AppConfig::default()
            }
        }
        1 => {
            let old: ConfigV1 =
                serde_json::from_value(value).map_err(|_| AppError::config_invalid())?;
            if old.schema_version != 1 {
                return Err(AppError::config_invalid());
            }
            AppConfig {
                selected_strategy: old.selected_strategy,
                log_retention_days: old.log_retention_days,
                ..AppConfig::default()
            }
        }
        2 => serde_json::from_value(value).map_err(|_| AppError::config_invalid())?,
        _ => return Err(AppError::config_unsupported()),
    };
    config.validate()?;
    Ok(config)
}

/// Prefer v2; read legacy only when v2 is absent. Migration is persisted on save.
/// Missing config means defaults; malformed files remain intact for recovery.
pub fn load_config(paths: &DataPaths) -> Result<AppConfig, AppError> {
    let file = match fs::File::open(&paths.config_file) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::File::open(&paths.legacy_config_file) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(AppConfig::default())
                }
                Err(_) => return Err(AppError::config_read()),
            }
        }
        Err(_) => return Err(AppError::config_read()),
    };
    if file.metadata().map_err(|_| AppError::config_read())?.len() > MAX_CONFIG_BYTES {
        return Err(AppError::config_invalid());
    }
    let mut data = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| AppError::config_read())?;
    decode_config(&data)
}

/// Writes a complete temp file then replaces the destination on the same volume.
pub fn save_config(paths: &DataPaths, config: &AppConfig) -> Result<(), AppError> {
    config.validate()?;
    fs::create_dir_all(&paths.config_dir).map_err(|_| AppError::config_write())?;
    let bytes = serde_json::to_vec_pretty(config).map_err(|_| AppError::config_invalid())?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(AppError::config_invalid());
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = paths
        .config_dir
        .join(format!(".v2.json.tmp-{}-{sequence}", std::process::id()));
    let result = (|| -> Result<(), AppError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|_| AppError::config_write())?;
        file.write_all(&bytes)
            .map_err(|_| AppError::config_write())?;
        file.sync_all().map_err(|_| AppError::config_write())?;
        drop(file);
        replace_file(&temp, &paths.config_file).map_err(|_| AppError::config_write())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let old: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let new: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let ok = unsafe {
        MoveFileExW(
            old.as_ptr(),
            new.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_strategy_basename_and_retention() {
        let mut config = AppConfig::default();
        config.selected_strategy = Some("general (ALT13).bat".into());
        assert!(config.validate().is_ok());
        for bad in [
            "../general.bat",
            "C:\\general.bat",
            "general/ALT.bat",
            "name. ",
            "",
        ] {
            config.selected_strategy = Some(bad.into());
            assert!(config.validate().is_err(), "accepted {bad}");
        }
        config.selected_strategy = None;
        config.log_retention_days = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn migrates_internal_v0_and_rejects_unknown_versions() {
        let migrated =
            decode_config(br#"{"schemaVersion":0,"selectedStrategy":"general (ALT13).bat"}"#)
                .unwrap();
        assert_eq!(migrated.schema_version, 2);
        assert_eq!(migrated.log_retention_days, 30);
        assert_eq!(migrated.appearance, AppearanceSettings::default());
        assert_eq!(
            migrated.selected_strategy.as_deref(),
            Some("general (ALT13).bat")
        );
        assert_eq!(
            decode_config(br#"{"schemaVersion":3}"#).unwrap_err().code,
            "config_version_unsupported"
        );
    }

    #[test]
    fn rejects_unknown_fields_and_oversized_files() {
        assert!(decode_config(br#"{"schemaVersion":1,"selectedStrategy":null,"logRetentionDays":30,"command":"evil"}"#).is_err());
        assert!(decode_config(&vec![b'x'; MAX_CONFIG_BYTES as usize + 1]).is_err());
    }

    #[test]
    fn appearance_rejects_paths_and_out_of_range_controls() {
        let asset = format!("{}.png", "a0".repeat(32));
        assert!(validate_asset_id(&asset));
        for invalid in [
            "../../asset.png".to_owned(),
            format!("{}.PNG", "a0".repeat(32)),
            format!("{}.jpg", "AB".repeat(32)),
            format!("{}.gif", "a0".repeat(32)),
            format!("{}.png", "a0".repeat(31)),
        ] {
            assert!(!validate_asset_id(&invalid), "accepted {invalid}");
            let appearance = AppearanceSettings {
                mascot_asset: Some(invalid),
                ..AppearanceSettings::default()
            };
            assert!(appearance.validate().is_err());
        }
        let good = AppearanceSettings {
            background_asset: Some(asset),
            background_opacity: 100,
            background_blur: 30,
            background_position_x: 0,
            background_position_y: 100,
            background_scale: 200,
            mascot_scale: 175,
            mascot_position_x: 100,
            mascot_position_y: 0,
            mascot_opacity: 0,
            dark_overlay: 90,
            ..AppearanceSettings::default()
        };
        assert!(good.validate().is_ok());
        for field in [
            "backgroundOpacity",
            "backgroundBlur",
            "backgroundPositionX",
            "backgroundPositionY",
            "mascotScale",
            "mascotPositionX",
            "mascotPositionY",
            "mascotOpacity",
            "darkOverlay",
        ] {
            let mut serialized = serde_json::to_value(&good).unwrap();
            serialized[field] = serde_json::json!(176);
            let invalid: AppearanceSettings = serde_json::from_value(serialized).unwrap();
            assert!(invalid.validate().is_err(), "accepted out of range {field}");
        }
        let small = AppearanceSettings {
            mascot_scale: 49,
            ..good
        };
        assert!(small.validate().is_err());
    }

    #[test]
    fn background_scale_defaults_for_existing_v2_config_and_rejects_out_of_range() {
        let mut json = serde_json::to_value(AppConfig::default()).unwrap();
        json["appearance"]
            .as_object_mut()
            .unwrap()
            .remove("backgroundScale");
        let existing = decode_config(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(existing.appearance.background_scale, 100);

        for scale in [49, 201] {
            json["appearance"]["backgroundScale"] = serde_json::json!(scale);
            assert!(decode_config(&serde_json::to_vec(&json).unwrap()).is_err());
        }
    }

    #[test]
    fn v2_requires_complete_appearance_and_rejects_unknown_fields() {
        let config = AppConfig::default();
        let mut json = serde_json::to_value(&config).unwrap();
        json["appearance"]["unrecognized"] = serde_json::json!(true);
        assert!(decode_config(&serde_json::to_vec(&json).unwrap()).is_err());
        let mut json = serde_json::to_value(&config).unwrap();
        json.as_object_mut().unwrap().remove("appearance");
        assert!(decode_config(&serde_json::to_vec(&json).unwrap()).is_err());
    }

    #[test]
    fn migrates_legacy_without_overwriting_files_and_never_falls_back_from_corrupt_v2() {
        let base = std::env::temp_dir().join(format!(
            "zapret-gui-config-migration-test-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let paths = DataPaths::from_local_appdata(&base).unwrap();
        fs::create_dir_all(&paths.config_dir).unwrap();
        let legacy = br#"{"schemaVersion":1,"selectedStrategy":"general (ALT13).bat","logRetentionDays":45}"#;
        fs::write(&paths.legacy_config_file, legacy).unwrap();
        let migrated = load_config(&paths).unwrap();
        assert_eq!(migrated.schema_version, 2);
        assert_eq!(
            migrated.selected_strategy.as_deref(),
            Some("general (ALT13).bat")
        );
        assert_eq!(migrated.log_retention_days, 45);
        assert_eq!(migrated.appearance, AppearanceSettings::default());
        assert!(!paths.config_file.exists());
        save_config(&paths, &migrated).unwrap();
        assert_eq!(fs::read(&paths.legacy_config_file).unwrap(), legacy);
        assert_eq!(load_config(&paths).unwrap(), migrated);
        fs::write(&paths.config_file, b"corrupt v2").unwrap();
        assert!(load_config(&paths).is_err());
        assert_eq!(fs::read(&paths.config_file).unwrap(), b"corrupt v2");
        assert_eq!(fs::read(&paths.legacy_config_file).unwrap(), legacy);
        fs::remove_file(&paths.config_file).unwrap();
        fs::write(&paths.legacy_config_file, b"corrupt legacy").unwrap();
        assert!(load_config(&paths).is_err());
        assert_eq!(
            fs::read(&paths.legacy_config_file).unwrap(),
            b"corrupt legacy"
        );
        assert!(!paths.config_file.exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn saves_replaces_and_preserves_old_file_on_validation_failure() {
        let base = std::env::temp_dir().join(format!(
            "zapret-gui-config-test-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&base).unwrap();
        let paths = DataPaths::from_local_appdata(&base).unwrap();
        let mut config = AppConfig::default();
        save_config(&paths, &config).unwrap();
        config.selected_strategy = Some("general (ALT13).bat".into());
        save_config(&paths, &config).unwrap();
        assert_eq!(load_config(&paths).unwrap(), config);
        let before = fs::read(&paths.config_file).unwrap();
        config.log_retention_days = 0;
        assert!(save_config(&paths, &config).is_err());
        assert_eq!(fs::read(&paths.config_file).unwrap(), before);
        fs::remove_dir_all(&base).unwrap();
    }
}
