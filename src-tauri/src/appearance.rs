//! Validated local copies of user-selected appearance images.

use crate::config::{validate_asset_id, AppearanceSettings, DataPaths};
use crate::error::AppError;
use image::codecs::webp::WebPDecoder;
use image::{ImageDecoder, ImageFormat, ImageReader, Limits};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIMENSION: u32 = 8192;
const MAX_PIXELS: u64 = 16_000_000;
const MAX_DECODE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ASSETS: usize = 64;
const MAX_STORE_BYTES: u64 = 128 * 1024 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedAsset {
    pub asset_id: String,
    pub mime: String,
}

/// Store verified original bytes under a content-addressed managed name.
pub fn import_asset(
    paths: &DataPaths,
    extension: &str,
    bytes: &[u8],
) -> Result<ImportedAsset, AppError> {
    let (format, canonical_extension, mime) = format_for_extension(extension)?;
    validate_image(bytes, format)?;
    let asset_id = format!("{:x}.{}", Sha256::digest(bytes), canonical_extension);
    if !validate_asset_id(&asset_id) {
        return Err(invalid("Не удалось создать безопасное имя изображения."));
    }
    check_managed_directory(&paths.appearance_dir, true)?;
    let destination = paths.appearance_dir.join(&asset_id);
    if destination.exists() {
        verify_existing(&destination, &asset_id)?;
        return Ok(ImportedAsset {
            asset_id,
            mime: mime.into(),
        });
    }
    let (count, total_bytes) = store_usage(&paths.appearance_dir)?;
    if count >= MAX_ASSETS || total_bytes.saturating_add(bytes.len() as u64) > MAX_STORE_BYTES {
        return Err(AppError::new(
            "appearance_storage_full",
            "Достигнут лимит локальных изображений оформления.",
            "Удалите ненужные изображения из папки оформления и повторите попытку.",
        ));
    }
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let temporary = paths
        .appearance_dir
        .join(format!(".import-{}-{serial}.tmp", std::process::id()));
    let outcome = (|| -> Result<(), AppError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| storage_error())?;
        file.write_all(bytes).map_err(|_| storage_error())?;
        file.sync_all().map_err(|_| storage_error())?;
        drop(file);
        match fs::rename(&temporary, &destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_existing(&destination, &asset_id)
            }
            Err(_) => Err(storage_error()),
        }
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    outcome?;
    Ok(ImportedAsset {
        asset_id,
        mime: mime.into(),
    })
}

/// Read only a named, content-addressed asset from the application's own data directory.
pub fn read_asset(paths: &DataPaths, asset_id: &str) -> Result<Vec<u8>, AppError> {
    if !validate_asset_id(asset_id) {
        return Err(invalid("Имя изображения содержит недопустимые символы."));
    }
    check_managed_directory(&paths.appearance_dir, false)?;
    let file_path = paths.appearance_dir.join(asset_id);
    let metadata = fs::symlink_metadata(&file_path).map_err(|_| missing())?;
    if !metadata.is_file() || is_reparse_point(&metadata) || metadata.len() > MAX_IMAGE_BYTES as u64
    {
        return Err(invalid(
            "Файл изображения не является допустимым обычным файлом.",
        ));
    }
    ensure_direct_child(&paths.appearance_dir, &file_path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(&file_path)
        .map_err(|_| missing())?
        .take(MAX_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| storage_error())?;
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(invalid("Изображение превышает предел 8 МиБ."));
    }
    let actual_id = format!(
        "{:x}.{}",
        Sha256::digest(&bytes),
        asset_id.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("")
    );
    if actual_id != asset_id {
        return Err(invalid("Содержимое локального изображения изменилось."));
    }
    let extension = asset_id.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    let (format, _, _) = format_for_extension(extension)?;
    validate_image(&bytes, format)?;
    Ok(bytes)
}

/// Reject settings that refer to missing, replaced, or unsupported local images.
pub fn verify_references(paths: &DataPaths, settings: &AppearanceSettings) -> Result<(), AppError> {
    if let Some(id) = &settings.background_asset {
        read_asset(paths, id)?;
    }
    if let Some(id) = &settings.mascot_asset {
        if settings.background_asset.as_deref() != Some(id) {
            read_asset(paths, id)?;
        }
    }
    Ok(())
}

/// Remove only unreferenced managed assets after the new configuration is durable.
/// Unrecognized names and links are left for manual inspection.
pub fn prune_unused(paths: &DataPaths, settings: &AppearanceSettings) -> Result<usize, AppError> {
    settings.validate()?;
    if !paths.appearance_dir.exists() {
        if settings.background_asset.is_some() || settings.mascot_asset.is_some() {
            return Err(missing());
        }
        return Ok(0);
    }
    check_managed_directory(&paths.appearance_dir, false)?;
    verify_references(paths, settings)?;
    let mut removed = 0;
    for entry in fs::read_dir(&paths.appearance_dir).map_err(|_| storage_error())? {
        let entry = entry.map_err(|_| storage_error())?;
        let name = entry.file_name();
        let Some(id) = name.to_str() else { continue };
        if !validate_asset_id(id)
            || settings.background_asset.as_deref() == Some(id)
            || settings.mascot_asset.as_deref() == Some(id)
        {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| storage_error())?;
        if !metadata.is_file() || is_reparse_point(&metadata) {
            continue;
        }
        ensure_direct_child(&paths.appearance_dir, &path)?;
        // A content-named file may have been modified locally; keep it for inspection.
        verify_existing(&path, id)?;
        fs::remove_file(&path).map_err(|_| storage_error())?;
        removed += 1;
    }
    Ok(removed)
}

fn format_for_extension(
    extension: &str,
) -> Result<(ImageFormat, &'static str, &'static str), AppError> {
    match extension
        .trim_start_matches('.')
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => Ok((ImageFormat::Png, "png", "image/png")),
        "jpg" | "jpeg" => Ok((ImageFormat::Jpeg, "jpg", "image/jpeg")),
        "webp" => Ok((ImageFormat::WebP, "webp", "image/webp")),
        _ => Err(invalid("Поддерживаются только PNG, JPEG и WebP.")),
    }
}

fn validate_image(bytes: &[u8], expected: ImageFormat) -> Result<(), AppError> {
    if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
        return Err(invalid("Файл пуст или превышает предел 8 МиБ."));
    }
    let actual = image::guess_format(bytes)
        .map_err(|_| invalid("Не удалось определить формат изображения."))?;
    if actual != expected {
        return Err(invalid(
            "Расширение файла не соответствует его содержимому.",
        ));
    }
    match actual {
        ImageFormat::Png if contains_png_animation(bytes)? => {
            return Err(invalid("Анимированный PNG не поддерживается."));
        }
        ImageFormat::WebP => {
            let decoder = WebPDecoder::new(Cursor::new(bytes))
                .map_err(|_| invalid("Файл WebP повреждён."))?;
            if decoder.has_animation() {
                return Err(invalid("Анимированный WebP не поддерживается."));
            }
            let (width, height) = decoder.dimensions();
            validate_dimensions(width, height)?;
        }
        _ => (),
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_BYTES);
    let mut reader = ImageReader::with_format(Cursor::new(bytes), actual);
    reader.limits(limits.clone());
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| invalid("Не удалось прочитать размеры изображения."))?;
    validate_dimensions(width, height)?;
    let mut reader = ImageReader::with_format(Cursor::new(bytes), actual);
    reader.limits(limits);
    let decoded = reader
        .decode()
        .map_err(|_| invalid("Изображение повреждено или требует слишком много памяти."))?;
    if decoded.width() != width || decoded.height() != height {
        return Err(invalid("Размер изображения изменился при декодировании."));
    }
    Ok(())
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), AppError> {
    if width == 0
        || height == 0
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || u64::from(width) * u64::from(height) > MAX_PIXELS
    {
        return Err(invalid(
            "Размер изображения превышает допустимые пределы: 8192 по стороне и 16 млн пикселей.",
        ));
    }
    Ok(())
}

/// Look at PNG chunk headers, not compressed image bytes, to detect APNG.
fn contains_png_animation(bytes: &[u8]) -> Result<bool, AppError> {
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(invalid("Повреждён заголовок PNG."));
    }
    let mut offset = 8usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(invalid("Повреждена структура PNG."));
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
            .ok_or_else(|| invalid("Повреждена структура PNG."))?;
        if end > bytes.len() {
            return Err(invalid("Повреждена структура PNG."));
        }
        let kind = &bytes[offset + 4..offset + 8];
        if kind == b"acTL" {
            return Ok(true);
        }
        offset = end;
        if kind == b"IEND" {
            return Ok(false);
        }
    }
    Err(invalid("PNG не содержит завершающий блок."))
}

fn check_managed_directory(path: &Path, create: bool) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        if create {
            fs::create_dir_all(parent).map_err(|_| storage_error())?;
        }
        let parent_metadata = fs::symlink_metadata(parent).map_err(|_| storage_error())?;
        if !parent_metadata.is_dir() || is_reparse_point(&parent_metadata) {
            return Err(invalid(
                "Папка данных приложения заменена ссылкой или другим файлом.",
            ));
        }
    }
    if create {
        match fs::create_dir(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(storage_error()),
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| missing())?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(invalid(
            "Папка оформления заменена ссылкой или другим файлом.",
        ));
    }
    Ok(())
}

fn ensure_direct_child(directory: &Path, file: &Path) -> Result<(), AppError> {
    let canonical_directory = fs::canonicalize(directory).map_err(|_| storage_error())?;
    let canonical_file = fs::canonicalize(file).map_err(|_| missing())?;
    if canonical_file.parent() != Some(canonical_directory.as_path()) {
        return Err(invalid(
            "Путь изображения выходит за пределы папки оформления.",
        ));
    }
    Ok(())
}

fn store_usage(path: &Path) -> Result<(usize, u64), AppError> {
    let mut count = 0;
    let mut total = 0u64;
    for entry in fs::read_dir(path).map_err(|_| storage_error())? {
        let entry = entry.map_err(|_| storage_error())?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| storage_error())?;
        if !metadata.is_file() || is_reparse_point(&metadata) {
            return Err(invalid(
                "В папке оформления найден неожиданный файл или ссылка.",
            ));
        }
        count += 1;
        total = total.saturating_add(metadata.len());
        if count > MAX_ASSETS || total > MAX_STORE_BYTES {
            break;
        }
    }
    Ok((count, total))
}

fn verify_existing(path: &Path, asset_id: &str) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| storage_error())?;
    if !metadata.is_file() || is_reparse_point(&metadata) || metadata.len() > MAX_IMAGE_BYTES as u64
    {
        return Err(invalid("Существующий файл оформления недопустим."));
    }
    ensure_direct_child(path.parent().ok_or_else(storage_error)?, path)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| storage_error())?
        .take(MAX_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| storage_error())?;
    let extension = asset_id.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    if format!("{:x}.{extension}", Sha256::digest(&bytes)) != asset_id {
        return Err(invalid(
            "Существующее изображение изменено; импорт остановлен.",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn invalid(detail: &'static str) -> AppError {
    AppError::new(
        "appearance_image_invalid",
        "Изображение оформления не подходит.",
        "Выберите статическое изображение PNG, JPEG или WebP размером до 8 МиБ.",
    )
    .with_detail(detail.into())
}

fn storage_error() -> AppError {
    AppError::new(
        "appearance_storage_failed",
        "Не удалось сохранить изображение оформления.",
        "Проверьте доступ и свободное место в папке данных приложения.",
    )
}

fn missing() -> AppError {
    AppError::new(
        "appearance_asset_missing",
        "Локальное изображение оформления не найдено.",
        "Выберите изображение снова или восстановите стандартное оформление.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_and_paths() -> (std::path::PathBuf, DataPaths) {
        let base = std::env::temp_dir().join(format!(
            "zapret-appearance-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&base).unwrap();
        let paths = DataPaths::from_local_appdata(&base).unwrap();
        (base, paths)
    }

    fn tiny_png() -> Vec<u8> {
        let mut bytes = Vec::new();
        image::DynamicImage::new_rgba8(1, 1)
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .unwrap();
        bytes
    }

    #[test]
    fn rejects_extension_mismatch_and_corruption() {
        let png = tiny_png();
        assert!(validate_image(&png, ImageFormat::Png).is_ok());
        assert!(validate_image(&png, ImageFormat::Jpeg).is_err());
        assert!(validate_image(b"not an image", ImageFormat::Png).is_err());
        assert!(format_for_extension("gif").is_err());
    }

    #[test]
    fn accepts_generated_jpeg_and_webp() {
        let (base, paths) = base_and_paths();
        for (extension, format, expected_mime) in [
            ("jpeg", ImageFormat::Jpeg, "image/jpeg"),
            ("webp", ImageFormat::WebP, "image/webp"),
        ] {
            let mut bytes = Vec::new();
            image::DynamicImage::new_rgba8(2, 2)
                .write_to(&mut Cursor::new(&mut bytes), format)
                .unwrap();
            let asset = import_asset(&paths, extension, &bytes).unwrap();
            assert_eq!(asset.mime, expected_mime);
            assert_eq!(read_asset(&paths, &asset.asset_id).unwrap(), bytes);
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rejects_png_animation_chunk_and_oversized_dimensions() {
        let mut png = tiny_png();
        png.splice(8..8, [0, 0, 0, 0, b'a', b'c', b'T', b'L', 0, 0, 0, 0]);
        assert!(contains_png_animation(&png).unwrap());
        assert!(validate_dimensions(8192, 8192).is_err());
        assert!(validate_dimensions(1, 1).is_ok());
        let valid = tiny_png();
        assert!(validate_image(&valid[..valid.len() - 8], ImageFormat::Png).is_err());
    }

    #[test]
    fn imported_asset_round_trips_and_detects_tampering() {
        let (base, paths) = base_and_paths();
        let png = tiny_png();
        let imported = import_asset(&paths, ".PNG", &png).unwrap();
        assert_eq!(imported.mime, "image/png");
        assert_eq!(read_asset(&paths, &imported.asset_id).unwrap(), png);
        assert_eq!(
            import_asset(&paths, "png", &png).unwrap().asset_id,
            imported.asset_id
        );
        assert!(import_asset(&paths, "jpg", &png).is_err());
        assert_eq!(read_asset(&paths, &imported.asset_id).unwrap(), png);
        fs::write(paths.appearance_dir.join(&imported.asset_id), b"tampered").unwrap();
        assert!(read_asset(&paths, &imported.asset_id).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn refuses_path_traversal() {
        let (base, paths) = base_and_paths();
        assert!(read_asset(&paths, "../other.png").is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn verifies_references_and_prunes_only_unused_managed_assets() {
        let (base, paths) = base_and_paths();
        let first = tiny_png();
        let mut alternate = image::RgbaImage::new(1, 1);
        alternate.put_pixel(0, 0, image::Rgba([5, 6, 7, 255]));
        let mut second = Vec::new();
        image::DynamicImage::ImageRgba8(alternate)
            .write_to(&mut Cursor::new(&mut second), ImageFormat::Png)
            .unwrap();
        let keep = import_asset(&paths, "png", &first).unwrap();
        let remove = import_asset(&paths, "png", &second).unwrap();
        let settings = AppearanceSettings {
            mascot_asset: Some(keep.asset_id.clone()),
            ..AppearanceSettings::default()
        };
        assert!(verify_references(&paths, &settings).is_ok());
        assert_eq!(prune_unused(&paths, &settings).unwrap(), 1);
        assert!(paths.appearance_dir.join(&keep.asset_id).exists());
        assert!(!paths.appearance_dir.join(&remove.asset_id).exists());
        let missing_settings = AppearanceSettings {
            background_asset: Some(format!("{}.png", "0".repeat(64))),
            ..AppearanceSettings::default()
        };
        assert!(verify_references(&paths, &missing_settings).is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
