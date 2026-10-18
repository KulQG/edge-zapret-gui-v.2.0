//! Strict extraction for official Flowseal ZIP releases.
//!
//! The extractor intentionally accepts a small ZIP subset instead of relying on
//! filesystem paths embedded in an archive. Each output path is reconstructed
//! beneath a newly-created staging directory after Windows-specific validation.

use crc32fast::Hasher;
use flate2::read::DeflateDecoder;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const MAX_EOCD_SEARCH: usize = 22 + u16::MAX as usize;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 50_000;
const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TOTAL_COMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 200;
const MAX_PATH_UTF16: usize = 240;
const MAX_COMPONENT_UTF16: usize = 255;

#[derive(Debug)]
pub(crate) struct ArchiveError(String);

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(value: io::Error) -> Self {
        Self(format!("Ошибка чтения ZIP-архива: {value}"))
    }
}

type Result<T> = std::result::Result<T, ArchiveError>;

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    relative: Option<PathBuf>,
    directory: bool,
    method: u16,
    flags: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
}

/// Extracts an official Flowseal release ZIP into `stage_dir`.
///
/// The archive must contain exactly one wrapper root named
/// `zapret-discord-youtube-{tag}`. The wrapper is removed from extracted paths.
/// `stage_dir` must not already exist; on any failure this function removes the
/// directory it created, leaving no partially extracted stage behind.
pub(crate) fn extract_flowseal_zip(archive_path: &Path, stage_dir: &Path, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    if stage_dir.exists() {
        return Err(ArchiveError("Каталог подготовки уже существует".into()));
    }
    let archive = File::open(archive_path)?;
    let metadata = archive.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_ARCHIVE_BYTES {
        return Err(ArchiveError(
            "Размер ZIP-архива превышает допустимый предел".into(),
        ));
    }
    fs::create_dir(stage_dir)?;
    let result = extract_open_archive(archive, metadata.len(), stage_dir, tag);
    if result.is_err() {
        let _ = fs::remove_dir_all(stage_dir);
    }
    result
}

fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty()
        || tag.len() > 64
        || !tag
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err(ArchiveError("Некорректная метка версии релиза".into()));
    }
    Ok(())
}

fn extract_open_archive(mut file: File, file_len: u64, stage_dir: &Path, tag: &str) -> Result<()> {
    let root = format!("zapret-discord-youtube-{tag}");
    let (entries, central_offset) = read_central_directory(&mut file, file_len, &root)?;
    validate_entry_set(&entries)?;
    let root_path = fs::canonicalize(stage_dir)?;
    let mut ranges = Vec::with_capacity(entries.len());
    let mut total_output = 0u64;
    let mut total_compressed = 0u64;

    for entry in &entries {
        if entry.directory {
            continue;
        }
        total_output = total_output
            .checked_add(entry.uncompressed_size)
            .ok_or_else(|| ArchiveError("Переполнение размера ZIP-архива".into()))?;
        total_compressed = total_compressed
            .checked_add(entry.compressed_size)
            .ok_or_else(|| ArchiveError("Переполнение размера ZIP-архива".into()))?;
        if total_output > MAX_TOTAL_BYTES || total_compressed > MAX_TOTAL_COMPRESSED_BYTES {
            return Err(ArchiveError(
                "Содержимое ZIP-архива превышает допустимый размер".into(),
            ));
        }
        if entry.uncompressed_size > MAX_ENTRY_BYTES {
            return Err(ArchiveError(format!("Файл «{}» слишком велик", entry.name)));
        }
        if entry.uncompressed_size > 0
            && (entry.compressed_size == 0
                || entry.uncompressed_size
                    > entry.compressed_size.saturating_mul(MAX_COMPRESSION_RATIO))
        {
            return Err(ArchiveError(format!(
                "Подозрительная степень сжатия файла «{}»",
                entry.name
            )));
        }
    }

    for entry in &entries {
        let data_start = validate_local_header(&mut file, file_len, central_offset, entry)?;
        let data_end = data_start
            .checked_add(entry.compressed_size)
            .ok_or_else(|| ArchiveError("Повреждённое смещение ZIP-данных".into()))?;
        if data_end > central_offset {
            return Err(ArchiveError(format!(
                "Данные файла «{}» выходят за границы архива",
                entry.name
            )));
        }
        if entry.directory {
            let range_end = descriptor_end(&mut file, file_len, entry, data_end)?;
            if range_end > central_offset {
                return Err(ArchiveError(format!(
                    "Дескриптор каталога «{}» пересекает каталог ZIP",
                    entry.name
                )));
            }
            ranges.push((entry.local_offset, range_end, entry.name.as_str()));
            if let Some(relative) = &entry.relative {
                let target = root_path.join(relative);
                ensure_beneath(&root_path, &target)?;
                fs::create_dir_all(&target)?;
            }
            continue;
        }
        let Some(relative) = &entry.relative else {
            return Err(ArchiveError(
                "Файл не может совпадать с корнем архива".into(),
            ));
        };
        let target = root_path.join(relative);
        ensure_beneath(&root_path, &target)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        ensure_beneath(&root_path, &target)?;
        file.seek(SeekFrom::Start(data_start))?;
        let compressed_len = usize::try_from(entry.compressed_size)
            .map_err(|_| ArchiveError("Размер файла не поддерживается".into()))?;
        let mut compressed = vec![0u8; compressed_len];
        file.read_exact(&mut compressed)?;
        let content = decode_entry(entry, &compressed)?;
        verify_crc(entry, &content)?;

        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        output.write_all(&content)?;
        output.sync_all()?;
        let range_end = descriptor_end(&mut file, file_len, entry, data_end)?;
        if range_end > central_offset {
            return Err(ArchiveError(format!(
                "Дескриптор файла «{}» пересекает каталог ZIP",
                entry.name
            )));
        }
        ranges.push((entry.local_offset, range_end, entry.name.as_str()));
    }
    verify_non_overlapping_ranges(&mut ranges)?;
    Ok(())
}

fn read_central_directory(file: &mut File, file_len: u64, root: &str) -> Result<(Vec<Entry>, u64)> {
    let tail_len = usize::try_from(file_len.min(MAX_EOCD_SEARCH as u64)).unwrap();
    file.seek(SeekFrom::Start(file_len - tail_len as u64))?;
    let mut tail = vec![0u8; tail_len];
    file.read_exact(&mut tail)?;
    let eocd_pos = tail
        .windows(4)
        .rposition(|w| read_u32(w, 0) == Some(EOCD_SIGNATURE))
        .ok_or_else(|| ArchiveError("В ZIP-архиве не найдена центральная запись".into()))?;
    if eocd_pos + 22 > tail.len() {
        return Err(ArchiveError("Обрезана запись окончания ZIP-архива".into()));
    }
    let eocd = &tail[eocd_pos..];
    let comment_len = read_u16(eocd, 20).unwrap() as usize;
    if eocd_pos + 22 + comment_len != tail.len() {
        return Err(ArchiveError(
            "Некорректная длина комментария ZIP-архива".into(),
        ));
    }
    let disk = read_u16(eocd, 4).unwrap();
    let central_disk = read_u16(eocd, 6).unwrap();
    let disk_count = read_u16(eocd, 8).unwrap();
    let count = read_u16(eocd, 10).unwrap();
    let central_size = read_u32(eocd, 12).unwrap();
    let central_offset = read_u32(eocd, 16).unwrap();
    if disk != 0 || central_disk != 0 || disk_count != count {
        return Err(ArchiveError(
            "Многотомные ZIP-архивы не поддерживаются".into(),
        ));
    }
    if count == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err(ArchiveError("ZIP64-архивы не поддерживаются".into()));
    }
    if count as usize > MAX_ENTRIES {
        return Err(ArchiveError("В ZIP-архиве слишком много записей".into()));
    }
    let eocd_absolute = file_len - tail_len as u64 + eocd_pos as u64;
    let central_end = (central_offset as u64)
        .checked_add(central_size as u64)
        .ok_or_else(|| ArchiveError("Некорректный размер центрального каталога".into()))?;
    if central_end != eocd_absolute || central_end > file_len {
        return Err(ArchiveError(
            "Некорректные границы центрального каталога ZIP".into(),
        ));
    }

    file.seek(SeekFrom::Start(central_offset as u64))?;
    let mut entries = Vec::with_capacity(count as usize);
    let mut consumed = 0u64;
    for _ in 0..count {
        let mut fixed = [0u8; 46];
        file.read_exact(&mut fixed)?;
        consumed += fixed.len() as u64;
        if read_u32(&fixed, 0) != Some(CENTRAL_SIGNATURE) {
            return Err(ArchiveError(
                "Повреждена запись центрального каталога ZIP".into(),
            ));
        }
        let flags = read_u16(&fixed, 8).unwrap();
        let method = read_u16(&fixed, 10).unwrap();
        let crc32 = read_u32(&fixed, 16).unwrap();
        let compressed_size = read_u32(&fixed, 20).unwrap();
        let uncompressed_size = read_u32(&fixed, 24).unwrap();
        let name_len = read_u16(&fixed, 28).unwrap() as usize;
        let extra_len = read_u16(&fixed, 30).unwrap() as usize;
        let comment_len = read_u16(&fixed, 32).unwrap() as usize;
        let start_disk = read_u16(&fixed, 34).unwrap();
        let external_attrs = read_u32(&fixed, 38).unwrap();
        let local_offset = read_u32(&fixed, 42).unwrap();
        if compressed_size == u32::MAX
            || uncompressed_size == u32::MAX
            || local_offset == u32::MAX
            || start_disk == u16::MAX
            || start_disk != 0
        {
            return Err(ArchiveError(
                "ZIP64 или многотомная запись не поддерживается".into(),
            ));
        }
        validate_flags_method(flags, method)?;
        let variable_len = name_len + extra_len + comment_len;
        consumed = consumed
            .checked_add(variable_len as u64)
            .ok_or_else(|| ArchiveError("Некорректная длина записи ZIP".into()))?;
        if consumed > central_size as u64 || name_len == 0 {
            return Err(ArchiveError(
                "Некорректная длина записи центрального каталога".into(),
            ));
        }
        let mut variable = vec![0u8; variable_len];
        file.read_exact(&mut variable)?;
        let raw_name = &variable[..name_len];
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| ArchiveError("В архиве найдено имя файла не в UTF-8".into()))?
            .to_owned();
        validate_extra_fields(&variable[name_len..name_len + extra_len])?;
        let directory = name.ends_with('/');
        validate_archive_name(&name, root)?;
        validate_attributes(external_attrs, directory)?;
        let relative = normalized_relative(&name, root, directory)?;
        if directory && (compressed_size != 0 || uncompressed_size != 0 || crc32 != 0) {
            return Err(ArchiveError(format!("Каталог «{name}» содержит данные")));
        }
        entries.push(Entry {
            name,
            relative,
            directory,
            method,
            flags,
            crc32,
            compressed_size: compressed_size as u64,
            uncompressed_size: uncompressed_size as u64,
            local_offset: local_offset as u64,
        });
    }
    if consumed != central_size as u64 {
        return Err(ArchiveError(
            "Центральный каталог содержит лишние или недостающие данные".into(),
        ));
    }
    Ok((entries, central_offset as u64))
}

fn validate_flags_method(flags: u16, method: u16) -> Result<()> {
    if flags & 1 != 0 {
        return Err(ArchiveError(
            "Зашифрованные ZIP-записи не поддерживаются".into(),
        ));
    }
    let allowed = 0x0800 | 0x0008 | if method == 8 { 0x0006 } else { 0 };
    if flags & !allowed != 0 {
        return Err(ArchiveError(
            "ZIP-запись использует неподдерживаемые флаги".into(),
        ));
    }
    if method != 0 && method != 8 {
        return Err(ArchiveError(
            "Поддерживаются только методы STORE и DEFLATE".into(),
        ));
    }
    Ok(())
}

fn validate_extra_fields(extra: &[u8]) -> Result<()> {
    let mut at = 0;
    while at < extra.len() {
        if at + 4 > extra.len() {
            return Err(ArchiveError("Повреждено дополнительное поле ZIP".into()));
        }
        let id = read_u16(extra, at).unwrap();
        let len = read_u16(extra, at + 2).unwrap() as usize;
        at += 4;
        if at + len > extra.len() {
            return Err(ArchiveError(
                "Повреждена длина дополнительного поля ZIP".into(),
            ));
        }
        if id == 0x0001 {
            return Err(ArchiveError("ZIP64-поля не поддерживаются".into()));
        }
        at += len;
    }
    Ok(())
}

fn validate_archive_name(name: &str, root: &str) -> Result<()> {
    if name.starts_with('/') || name.starts_with('\\') || name.contains('\\') || name.contains('\0')
    {
        return Err(ArchiveError(format!("Недопустимый путь в ZIP: «{name}»")));
    }
    let prefix = format!("{root}/");
    if name != prefix.trim_end_matches('/') && !name.starts_with(&prefix) {
        return Err(ArchiveError(format!(
            "Запись «{name}» находится вне ожидаемого каталога релиза"
        )));
    }
    if name.matches(':').count() > 0 {
        return Err(ArchiveError(format!(
            "Путь «{name}» содержит недопустимый символ"
        )));
    }
    let parts: Vec<&str> = name.trim_end_matches('/').split('/').collect();
    if parts.first().copied() != Some(root) || parts.len() > 64 {
        return Err(ArchiveError(format!(
            "Недопустимая структура пути в ZIP: «{name}»"
        )));
    }
    if name.encode_utf16().count() > MAX_PATH_UTF16 {
        return Err(ArchiveError(format!(
            "Слишком длинный путь в ZIP: «{name}»"
        )));
    }
    for part in parts {
        let units = part.encode_utf16().count();
        if part.is_empty()
            || part == "."
            || part == ".."
            || units > MAX_COMPONENT_UTF16
            || part.ends_with(' ')
            || part.ends_with('.')
            || part
                .chars()
                .any(|c| c < ' ' || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
            || is_reserved_windows_name(part)
        {
            return Err(ArchiveError(format!(
                "Недопустимое имя файла в ZIP: «{part}»"
            )));
        }
    }
    Ok(())
}

fn is_reserved_windows_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        upper
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
    })
}

fn validate_attributes(attrs: u32, directory: bool) -> Result<()> {
    let dos_attrs = attrs & 0xffff;
    if dos_attrs & 0x0400 != 0 {
        return Err(ArchiveError(
            "Записи с атрибутом reparse point запрещены".into(),
        ));
    }
    let unix_mode = attrs >> 16;
    let file_type = unix_mode & 0xf000;
    if file_type == 0xa000 || (file_type != 0 && file_type != 0x8000 && file_type != 0x4000) {
        return Err(ArchiveError(
            "Ссылки и специальные файлы в ZIP запрещены".into(),
        ));
    }
    if (file_type == 0x4000) != directory && file_type != 0 {
        return Err(ArchiveError("Тип записи ZIP не совпадает с именем".into()));
    }
    Ok(())
}

fn normalized_relative(name: &str, root: &str, directory: bool) -> Result<Option<PathBuf>> {
    if name.trim_end_matches('/') == root {
        return if directory {
            Ok(None)
        } else {
            Err(ArchiveError("Корень архива должен быть каталогом".into()))
        };
    }
    let stripped = name
        .strip_prefix(&format!("{root}/"))
        .ok_or_else(|| ArchiveError("Запись находится вне корня релиза".into()))?;
    let stripped = stripped.trim_end_matches('/');
    let mut path = PathBuf::new();
    for part in stripped.split('/') {
        if part.is_empty() {
            return Err(ArchiveError("Путь в ZIP содержит пустой компонент".into()));
        }
        path.push(part);
    }
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(ArchiveError(
            "Путь в ZIP содержит недопустимый компонент".into(),
        ));
    }
    Ok(Some(path))
}

fn validate_entry_set(entries: &[Entry]) -> Result<()> {
    let mut names = HashSet::new();
    let mut kinds = std::collections::HashMap::<String, bool>::new();
    let mut component_spellings = std::collections::HashMap::<String, String>::new();
    let mut local_offsets = HashSet::new();
    for entry in entries {
        let key = entry.name.trim_end_matches('/').to_lowercase();
        if !names.insert(key.clone()) {
            return Err(ArchiveError(format!(
                "В ZIP повторяется имя «{}» без учёта регистра",
                entry.name
            )));
        }
        if !local_offsets.insert(entry.local_offset) {
            return Err(ArchiveError(
                "Несколько ZIP-записей ссылаются на один заголовок".into(),
            ));
        }
        kinds.insert(key, entry.directory);
        let components: Vec<&str> = entry.name.trim_end_matches('/').split('/').collect();
        let mut prefix = String::new();
        for component in components {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let folded = prefix.to_lowercase();
            if component_spellings
                .get(&folded)
                .is_some_and(|existing| existing != &prefix)
            {
                return Err(ArchiveError(format!(
                    "В ZIP повторяется путь с разным регистром: «{prefix}»"
                )));
            }
            component_spellings
                .entry(folded)
                .or_insert_with(|| prefix.clone());
        }
    }
    for entry in entries {
        let path = entry.name.trim_end_matches('/');
        let components: Vec<&str> = path.split('/').collect();
        let mut parent = String::new();
        for component in &components[..components.len().saturating_sub(1)] {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            if kinds
                .get(&parent.to_lowercase())
                .is_some_and(|is_dir| !is_dir)
            {
                return Err(ArchiveError(format!(
                    "Файл используется как каталог: «{parent}»"
                )));
            }
        }
    }
    Ok(())
}

fn validate_local_header(
    file: &mut File,
    file_len: u64,
    central_offset: u64,
    entry: &Entry,
) -> Result<u64> {
    if entry.local_offset + 30 > file_len || entry.local_offset >= central_offset {
        return Err(ArchiveError(format!(
            "Заголовок файла «{}» выходит за границы архива",
            entry.name
        )));
    }
    file.seek(SeekFrom::Start(entry.local_offset))?;
    let mut fixed = [0u8; 30];
    file.read_exact(&mut fixed)?;
    if read_u32(&fixed, 0) != Some(LOCAL_SIGNATURE) {
        return Err(ArchiveError(format!(
            "Повреждён локальный заголовок «{}»",
            entry.name
        )));
    }
    let flags = read_u16(&fixed, 6).unwrap();
    let method = read_u16(&fixed, 8).unwrap();
    let crc = read_u32(&fixed, 14).unwrap();
    let compressed = read_u32(&fixed, 18).unwrap();
    let uncompressed = read_u32(&fixed, 22).unwrap();
    let name_len = read_u16(&fixed, 26).unwrap() as usize;
    let extra_len = read_u16(&fixed, 28).unwrap() as usize;
    if flags != entry.flags || method != entry.method {
        return Err(ArchiveError(format!(
            "Локальный заголовок «{}» не совпадает с каталогом",
            entry.name
        )));
    }
    let descriptor = flags & 0x0008 != 0;
    if (!descriptor
        && (crc != entry.crc32
            || compressed as u64 != entry.compressed_size
            || uncompressed as u64 != entry.uncompressed_size))
        || (descriptor
            && !((crc == 0 && compressed == 0 && uncompressed == 0)
                || (crc == entry.crc32
                    && compressed as u64 == entry.compressed_size
                    && uncompressed as u64 == entry.uncompressed_size)))
    {
        return Err(ArchiveError(format!(
            "Размеры локального заголовка «{}» не совпадают",
            entry.name
        )));
    }
    let mut name = vec![0u8; name_len];
    file.read_exact(&mut name)?;
    if name != entry.name.as_bytes() {
        return Err(ArchiveError(format!(
            "Имя в локальном заголовке «{}» не совпадает",
            entry.name
        )));
    }
    let mut extra = vec![0u8; extra_len];
    file.read_exact(&mut extra)?;
    validate_extra_fields(&extra)?;
    Ok(entry.local_offset + 30 + name_len as u64 + extra_len as u64)
}

fn decode_entry(entry: &Entry, compressed: &[u8]) -> Result<Vec<u8>> {
    let expected = usize::try_from(entry.uncompressed_size)
        .map_err(|_| ArchiveError("Размер распакованного файла не поддерживается".into()))?;
    let mut output = Vec::with_capacity(expected);
    match entry.method {
        0 => output.extend_from_slice(compressed),
        8 => {
            let cursor = Cursor::new(compressed);
            let mut decoder = DeflateDecoder::new(cursor);
            decoder
                .by_ref()
                .take(entry.uncompressed_size.saturating_add(1))
                .read_to_end(&mut output)
                .map_err(|e| {
                    ArchiveError(format!("Не удалось распаковать «{}»: {e}", entry.name))
                })?;
            if decoder.total_in() as u64 != entry.compressed_size {
                return Err(ArchiveError(format!(
                    "В сжатых данных «{}» есть лишние байты",
                    entry.name
                )));
            }
        }
        _ => return Err(ArchiveError("Неподдерживаемый метод сжатия".into())),
    }
    if output.len() as u64 != entry.uncompressed_size {
        return Err(ArchiveError(format!(
            "Размер распакованного файла «{}» не совпадает",
            entry.name
        )));
    }
    Ok(output)
}

fn verify_crc(entry: &Entry, content: &[u8]) -> Result<()> {
    let mut hasher = Hasher::new();
    hasher.update(content);
    if hasher.finalize() != entry.crc32 {
        return Err(ArchiveError(format!(
            "Контрольная сумма файла «{}» не совпадает",
            entry.name
        )));
    }
    Ok(())
}

fn descriptor_end(file: &mut File, file_len: u64, entry: &Entry, data_end: u64) -> Result<u64> {
    if entry.flags & 0x0008 == 0 {
        return Ok(data_end);
    }
    if data_end + 12 > file_len {
        return Err(ArchiveError(format!(
            "Обрезан дескриптор файла «{}»",
            entry.name
        )));
    }
    file.seek(SeekFrom::Start(data_end))?;
    let mut first = [0u8; 4];
    file.read_exact(&mut first)?;
    let has_signature = read_u32(&first, 0) == Some(DESCRIPTOR_SIGNATURE);
    let crc = if has_signature {
        let mut b = [0u8; 4];
        file.read_exact(&mut b)?;
        read_u32(&b, 0).unwrap()
    } else {
        read_u32(&first, 0).unwrap()
    };
    let mut sizes = [0u8; 8];
    file.read_exact(&mut sizes)?;
    let compressed = read_u32(&sizes, 0).unwrap();
    let uncompressed = read_u32(&sizes, 4).unwrap();
    if crc != entry.crc32
        || compressed as u64 != entry.compressed_size
        || uncompressed as u64 != entry.uncompressed_size
    {
        return Err(ArchiveError(format!(
            "Дескриптор файла «{}» не совпадает",
            entry.name
        )));
    }
    Ok(data_end + if has_signature { 16 } else { 12 })
}

fn verify_non_overlapping_ranges(ranges: &mut Vec<(u64, u64, &str)>) -> Result<()> {
    ranges.sort_by_key(|r| r.0);
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(ArchiveError(format!(
                "Данные ZIP-записей «{}» и «{}» пересекаются",
                pair[0].2, pair[1].2
            )));
        }
    }
    Ok(())
}

fn ensure_beneath(root: &Path, target: &Path) -> Result<()> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| ArchiveError("Путь распаковки вышел за пределы каталога подготовки".into()))?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(ArchiveError("Недопустимый путь распаковки".into()));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "zapret-archive-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut local = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let offset = local.len() as u32;
            let crc = crc(data);
            local.extend_from_slice(&LOCAL_SIGNATURE.to_le_bytes());
            local.extend_from_slice(&20u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&crc.to_le_bytes());
            local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            local.extend_from_slice(&(name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(name.as_bytes());
            local.extend_from_slice(data);

            central.extend_from_slice(&CENTRAL_SIGNATURE.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let central_offset = local.len() as u32;
        let central_len = central.len() as u32;
        local.extend_from_slice(&central);
        local.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        local.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        local.extend_from_slice(&central_len.to_le_bytes());
        local.extend_from_slice(&central_offset.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local
    }

    fn crc(data: &[u8]) -> u32 {
        let mut h = Hasher::new();
        h.update(data);
        h.finalize()
    }

    fn extract_fixture(bytes: &[u8], label: &str) -> (Result<()>, PathBuf) {
        let base = temp_dir(label);
        fs::create_dir_all(&base).unwrap();
        let archive = base.join("bundle.zip");
        let stage = base.join("stage");
        fs::write(&archive, bytes).unwrap();
        let result = extract_flowseal_zip(&archive, &stage, "1.2.3");
        (result, stage)
    }

    #[test]
    fn extracts_valid_release_and_removes_wrapper() {
        let bytes = zip(&[("zapret-discord-youtube-1.2.3/bin/winws.exe", b"engine")]);
        let (result, stage) = extract_fixture(&bytes, "valid");
        result.unwrap();
        assert_eq!(fs::read(stage.join("bin/winws.exe")).unwrap(), b"engine");
        let _ = fs::remove_dir_all(stage.parent().unwrap());
    }

    #[test]
    fn rejects_zip_slip_and_cleans_stage() {
        let bytes = zip(&[("zapret-discord-youtube-1.2.3/../../escape.txt", b"bad")]);
        let (result, stage) = extract_fixture(&bytes, "slip");
        assert!(result.is_err());
        assert!(!stage.exists());
        let _ = fs::remove_dir_all(stage.parent().unwrap());
    }

    #[test]
    fn rejects_case_insensitive_duplicate_names() {
        let bytes = zip(&[
            ("zapret-discord-youtube-1.2.3/bin/a.dll", b"a"),
            ("zapret-discord-youtube-1.2.3/BIN/A.DLL", b"b"),
        ]);
        let (result, stage) = extract_fixture(&bytes, "duplicate");
        assert!(result.is_err());
        assert!(!stage.exists());
        let _ = fs::remove_dir_all(stage.parent().unwrap());
    }

    #[test]
    fn rejects_windows_special_names_and_ads() {
        assert!(validate_archive_name(
            "zapret-discord-youtube-1.2.3/CON.txt",
            "zapret-discord-youtube-1.2.3"
        )
        .is_err());
        assert!(validate_archive_name(
            "zapret-discord-youtube-1.2.3/file:stream",
            "zapret-discord-youtube-1.2.3"
        )
        .is_err());
    }

    #[test]
    fn rejects_bad_crc_and_removes_stage() {
        let mut bytes = zip(&[("zapret-discord-youtube-1.2.3/data.txt", b"hello")]);
        // Change both recorded CRCs while leaving the payload unchanged.
        let central = bytes
            .windows(4)
            .position(|w| read_u32(w, 0) == Some(CENTRAL_SIGNATURE))
            .unwrap();
        bytes[central + 16] ^= 0x80;
        bytes[14] ^= 0x80;
        let (result, stage) = extract_fixture(&bytes, "crc");
        assert!(result.is_err());
        assert!(!stage.exists());
        let _ = fs::remove_dir_all(stage.parent().unwrap());
    }

    #[test]
    fn rejects_declared_size_over_limit_before_writing() {
        let mut bytes = zip(&[("zapret-discord-youtube-1.2.3/data.txt", b"hello")]);
        let central = bytes
            .windows(4)
            .position(|w| read_u32(w, 0) == Some(CENTRAL_SIGNATURE))
            .unwrap();
        bytes[central + 24..central + 28]
            .copy_from_slice(&((MAX_ENTRY_BYTES as u32) + 1).to_le_bytes());
        let (result, stage) = extract_fixture(&bytes, "size");
        assert!(result.is_err());
        assert!(!stage.exists());
        let _ = fs::remove_dir_all(stage.parent().unwrap());
    }
}
