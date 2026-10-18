//! Security checks for the shared, privileged engine directory.
//!
//! This module deliberately fails closed. Existing directories with an unexpected
//! owner, DACL, or reparse point are never repaired or adopted automatically.

use crate::error::AppError;
use std::path::{Path, PathBuf};

const ENGINE_ACL_SDDL: &str = "O:BA G:SY D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";
const MAX_ENGINE_NODES: usize = 100_000;
const WRITE_ACCESS_BITS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x0100_0000
    | 0x0200_0000
    | 0x4000_0000
    | 0x1000_0000;

fn mask_grants_write(mask: u32) -> bool {
    mask & WRITE_ACCESS_BITS != 0
}

fn storage_error(path: &Path, detail: impl Into<String>) -> AppError {
    AppError::new(
        "engine_storage_security",
        "Папка движка не прошла проверку безопасности.",
        "Не меняйте разрешения вручную. Проверьте путь и ACL папки; затем повторите операцию или переустановите приложение.",
    )
    .with_detail(format!("{}: {}", path.display(), detail.into()))
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::{
        ffi::OsStr,
        iter,
        os::windows::{ffi::OsStrExt, fs::MetadataExt},
    };
    use windows_sys::Win32::{
        Foundation::{LocalFree, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE},
        Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        },
        Security::{
            AclSizeInformation, CreateWellKnownSid, EqualSid, GetAce, GetAclInformation,
            GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
            WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE,
            ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, WELL_KNOWN_SID_TYPE,
        },
        Storage::FileSystem::{CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT},
        System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
    };

    const GENERIC_BITS: u32 = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    const ACE_INHERIT_ONLY: u8 = 0x08;

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(iter::once(0)).collect()
    }

    fn trusted_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<[u32; 4], String> {
        let mut sid = [0u32; 4];
        let mut size = std::mem::size_of_val(&sid) as u32;
        // Four u32s are enough for the two fixed well-known SIDs used here.
        unsafe {
            if CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            ) == 0
            {
                return Err(format!(
                    "CreateWellKnownSid failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(sid)
    }

    fn sid_is(sid: *mut core::ffi::c_void, expected: &[u32]) -> bool {
        unsafe { EqualSid(sid, expected.as_ptr().cast_mut().cast()) != 0 }
    }

    fn is_trusted_owner(owner: *mut core::ffi::c_void) -> Result<bool, String> {
        let system = trusted_sid(WinLocalSystemSid)?;
        let admins = trusted_sid(WinBuiltinAdministratorsSid)?;
        Ok(sid_is(owner, &system) || sid_is(owner, &admins))
    }

    fn is_trustedinstaller(owner: *mut core::ffi::c_void) -> bool {
        // S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
        // (the standard Windows TrustedInstaller service SID).
        const TRUSTEDINSTALLER_SID: [u32; 8] = [
            0x0000_0601,
            0x0500_0000,
            80,
            956_008_885,
            3_418_522_649,
            1_831_038_044,
            1_853_292_631,
            2_271_478_464,
        ];
        sid_is(owner, &TRUSTEDINSTALLER_SID)
    }

    fn is_privileged_sid(
        sid: *mut core::ffi::c_void,
        system: &[u32; 4],
        admins: &[u32; 4],
    ) -> bool {
        is_trustedinstaller(sid) || sid_is(sid, system) || sid_is(sid, admins)
    }

    struct SecurityDescriptor(*mut core::ffi::c_void);
    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    fn get_descriptor(path: &Path) -> Result<SecurityDescriptor, String> {
        let path_w = wide(path.as_os_str());
        let mut descriptor = std::ptr::null_mut();
        let code = unsafe {
            GetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if code != 0 {
            return Err(format!("GetNamedSecurityInfoW: Win32 error {code}"));
        }
        if descriptor.is_null() {
            return Err("Windows returned an empty security descriptor".to_owned());
        }
        Ok(SecurityDescriptor(descriptor))
    }

    fn check_descriptor(path: &Path, require_protected_dacl: bool) -> Result<(), String> {
        check_descriptor_impl(path, require_protected_dacl, false)
    }

    fn check_descriptor_impl(
        path: &Path,
        require_protected_dacl: bool,
        installed_path: bool,
    ) -> Result<(), String> {
        let descriptor = get_descriptor(path)?;
        validate_descriptor(&descriptor, require_protected_dacl, installed_path)
    }

    fn validate_descriptor(
        descriptor: &SecurityDescriptor,
        require_protected_dacl: bool,
        installed_path: bool,
    ) -> Result<(), String> {
        let mut owner = std::ptr::null_mut();
        let mut owner_defaulted = 0;
        unsafe {
            if GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut owner_defaulted) == 0 {
                return Err(format!(
                    "GetSecurityDescriptorOwner: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        if owner.is_null()
            || (!is_trusted_owner(owner)? && !(installed_path && is_trustedinstaller(owner)))
        {
            return Err(
                "владелец должен быть SYSTEM или встроенной группой Администраторы".to_owned(),
            );
        }

        let mut dacl_present = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_defaulted = 0;
        unsafe {
            if GetSecurityDescriptorDacl(
                descriptor.0,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            ) == 0
            {
                return Err(format!(
                    "GetSecurityDescriptorDacl: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        // A null or absent DACL grants unrestricted access.
        if dacl_present == 0 || dacl.is_null() {
            return Err("отсутствует ограничивающий DACL".to_owned());
        }

        if require_protected_dacl {
            let mut control = 0u16;
            let mut revision = 0u32;
            unsafe {
                if GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) == 0 {
                    return Err(format!(
                        "GetSecurityDescriptorControl: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            if control & SE_DACL_PROTECTED == 0 {
                return Err("DACL каталога движка наследуется от внешней папки".to_owned());
            }
        }

        let system = trusted_sid(WinLocalSystemSid)?;
        let admins = trusted_sid(WinBuiltinAdministratorsSid)?;
        let mut size_info = ACL_SIZE_INFORMATION::default();
        unsafe {
            if GetAclInformation(
                dacl,
                (&mut size_info as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == 0
            {
                return Err(format!(
                    "GetAclInformation: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        for index in 0..size_info.AceCount {
            let mut raw_ace = std::ptr::null_mut();
            unsafe {
                if GetAce(dacl, index, &mut raw_ace) == 0 {
                    return Err(format!("GetAce: {}", std::io::Error::last_os_error()));
                }
            }
            if raw_ace.is_null() {
                return Err("DACL содержит пустую запись".to_owned());
            }
            let header = unsafe { &*(raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>()) };
            // Installed Program Files ancestors may have a Creator Owner
            // inherit-only ACE. It grants nothing on this object, and each
            // descendant on the executable's path is checked separately.
            // Engine directories must also be safe for newly extracted files,
            // so an inheritable untrusted write grant is rejected there.
            if installed_path && header.AceFlags & ACE_INHERIT_ONLY != 0 {
                continue;
            }
            match header.AceType as u32 {
                ACCESS_DENIED_ACE_TYPE => {
                    let ace = unsafe { &*(raw_ace.cast::<ACCESS_DENIED_ACE>()) };
                    if (ace.Mask & GENERIC_BITS) != 0 {
                        return Err("DACL содержит неподдерживаемую generic deny-запись".to_owned());
                    }
                }
                ACCESS_ALLOWED_ACE_TYPE => {
                    let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
                    let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
                    if mask_grants_write(ace.Mask) && !is_privileged_sid(sid, &system, &admins) {
                        return Err(format!(
                            "DACL разрешает запись непривилегированной SID (ACE #{index})"
                        ));
                    }
                }
                other => return Err(format!("DACL содержит неподдерживаемый тип ACE {other}")),
            }
        }
        Ok(())
    }

    fn ensure_directory_no_reparse(path: &Path) -> Result<bool, AppError> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    || metadata.file_type().is_symlink()
                {
                    return Err(storage_error(path, "путь является reparse point / ссылкой"));
                }
                if !metadata.is_dir() {
                    return Err(storage_error(path, "путь существует, но это не каталог"));
                }
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(storage_error(
                path,
                format!("не удалось проверить путь: {e}"),
            )),
        }
    }

    fn descriptor_from_sddl(sddl: &str) -> Result<SecurityDescriptor, String> {
        let mut descriptor = std::ptr::null_mut();
        let sddl: Vec<u16> = sddl.encode_utf16().chain(iter::once(0)).collect();
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(format!(
                    "Не удалось создать ACL: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(SecurityDescriptor(descriptor))
    }

    fn create_protected_directory(path: &Path) -> Result<(), AppError> {
        let descriptor =
            descriptor_from_sddl(ENGINE_ACL_SDDL).map_err(|why| storage_error(path, why))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let path_w = wide(path.as_os_str());
        unsafe {
            if CreateDirectoryW(path_w.as_ptr(), &attributes) == 0 {
                return Err(storage_error(
                    path,
                    format!(
                        "Не удалось создать защищённый каталог: {}",
                        std::io::Error::last_os_error()
                    ),
                ));
            }
        }
        Ok(())
    }

    fn validate_engine_tree(root: &Path) -> Result<(), AppError> {
        let mut stack = vec![root.to_path_buf()];
        let mut visited = 0usize;
        while let Some(path) = stack.pop() {
            visited += 1;
            if visited > MAX_ENGINE_NODES {
                return Err(storage_error(
                    root,
                    "в дереве движка слишком много объектов",
                ));
            }
            let metadata = std::fs::symlink_metadata(&path).map_err(|e| {
                storage_error(&path, format!("не удалось прочитать метаданные: {e}"))
            })?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || metadata.file_type().is_symlink()
            {
                return Err(storage_error(
                    &path,
                    "в дереве движка обнаружена ссылка или reparse point",
                ));
            }
            check_descriptor(&path, false).map_err(|why| storage_error(&path, why))?;
            if metadata.is_dir() {
                let entries = std::fs::read_dir(&path).map_err(|e| {
                    storage_error(&path, format!("не удалось просмотреть каталог: {e}"))
                })?;
                for entry in entries {
                    let entry = entry.map_err(|e| {
                        storage_error(&path, format!("ошибка чтения элемента: {e}"))
                    })?;
                    stack.push(entry.path());
                }
            }
        }
        Ok(())
    }

    fn validate_engine_base(
        program_data: &Path,
        app_root: &Path,
        engine: &Path,
    ) -> Result<(), AppError> {
        if !ensure_directory_no_reparse(program_data)? {
            return Err(storage_error(
                program_data,
                "системная папка ProgramData отсутствует",
            ));
        }
        if ensure_directory_no_reparse(app_root)? {
            check_descriptor(app_root, true).map_err(|why| storage_error(app_root, why))?;
        }
        if ensure_directory_no_reparse(engine)? {
            check_descriptor(engine, true).map_err(|why| storage_error(engine, why))?;
        }
        // Validate the entire replaceable engine tree (current, staging, rollback,
        // and archives) before privileged code consumes or replaces any part.
        if ensure_directory_no_reparse(engine)? {
            validate_engine_tree(engine)?;
        }
        Ok(())
    }

    pub(crate) fn prepare_engine_storage() -> Result<PathBuf, AppError> {
        let current = crate::diagnostics::engine_dir()
            .map_err(|e| storage_error(Path::new("ProgramData"), e))?;
        let engine = current
            .parent()
            .ok_or_else(|| storage_error(&current, "неверный путь движка"))?;
        let app_root = engine
            .parent()
            .ok_or_else(|| storage_error(engine, "неверный путь корневого каталога"))?;
        let program_data = app_root
            .parent()
            .ok_or_else(|| storage_error(app_root, "неверный путь ProgramData"))?;
        validate_engine_base(program_data, app_root, engine)?;

        if !ensure_directory_no_reparse(app_root)? {
            create_protected_directory(app_root)?;
            check_descriptor(app_root, true).map_err(|why| storage_error(app_root, why))?;
        }
        if !ensure_directory_no_reparse(engine)? {
            create_protected_directory(engine)?;
            check_descriptor(engine, true).map_err(|why| storage_error(engine, why))?;
        }
        validate_engine_base(program_data, app_root, engine)?;
        Ok(current)
    }

    pub(crate) fn verify_engine_storage() -> Result<(), AppError> {
        let current = crate::diagnostics::engine_dir()
            .map_err(|e| storage_error(Path::new("ProgramData"), e))?;
        let engine = current
            .parent()
            .ok_or_else(|| storage_error(&current, "неверный путь движка"))?;
        let app_root = engine
            .parent()
            .ok_or_else(|| storage_error(engine, "неверный путь корневого каталога"))?;
        let program_data = app_root
            .parent()
            .ok_or_else(|| storage_error(app_root, "неверный путь ProgramData"))?;
        if !ensure_directory_no_reparse(app_root)? || !ensure_directory_no_reparse(engine)? {
            return Err(storage_error(
                engine,
                "защищённая папка движка ещё не создана",
            ));
        }
        validate_engine_base(program_data, app_root, engine)
    }

    pub(crate) fn verify_protected_path(path: &Path) -> Result<(), AppError> {
        // Check the supplied path before canonicalization: canonicalize follows
        // reparse points, while this boundary must reject them.
        if !path.is_absolute() {
            return Err(storage_error(path, "путь должен быть абсолютным"));
        }
        for node in path.ancestors() {
            if let Ok(metadata) = std::fs::symlink_metadata(node) {
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    || metadata.file_type().is_symlink()
                {
                    return Err(storage_error(
                        node,
                        "путь содержит ссылку или reparse point",
                    ));
                }
            } else if node == path {
                return Err(storage_error(path, "проверяемый файл отсутствует"));
            }
        }
        let path = path.canonicalize().map_err(|e| {
            storage_error(path, format!("не удалось разрешить проверяемый путь: {e}"))
        })?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| storage_error(&path, format!("не удалось проверить файл: {e}")))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.file_type().is_symlink()
            || metadata.is_dir()
        {
            return Err(storage_error(
                &path,
                "ожидался обычный файл без reparse point",
            ));
        }
        check_descriptor_impl(&path, false, true).map_err(|why| storage_error(&path, why))?;
        let program_files = crate::diagnostics::program_files_dir()
            .map_err(|e| storage_error(&path, e))?
            .canonicalize()
            .map_err(|e| {
                storage_error(&path, format!("не удалось проверить Program Files: {e}"))
            })?;
        let parent = path
            .parent()
            .ok_or_else(|| storage_error(&path, "у файла отсутствует родительская папка"))?;
        if !parent.starts_with(&program_files) {
            return Err(storage_error(
                &path,
                "файл находится за пределами Program Files",
            ));
        }
        for node in parent
            .ancestors()
            .take_while(|node| node.starts_with(&program_files))
        {
            ensure_directory_no_reparse(node)?;
            // Installed files and their ancestors may also be owned by the
            // Windows TrustedInstaller service, unlike the managed engine.
            check_descriptor_impl(node, false, true).map_err(|why| storage_error(node, why))?;
            if node == program_files {
                break;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod descriptor_tests {
        use super::*;

        fn check(sddl: &str, protected: bool, installed_path: bool) -> Result<(), String> {
            let descriptor = descriptor_from_sddl(sddl).unwrap();
            validate_descriptor(&descriptor, protected, installed_path)
        }

        #[test]
        fn protected_engine_descriptor_allows_privileged_write_and_users_read_execute() {
            check(ENGINE_ACL_SDDL, true, false).unwrap();
        }

        #[test]
        fn unprivileged_write_grants_are_rejected() {
            for permission in ["FW", "WD", "WO", "GA", "GW", "0x00000004"] {
                let descriptor = format!("O:BAG:SYD:P(A;;{permission};;;BU)");
                assert!(check(&descriptor, true, false).is_err(), "{descriptor}");
            }
            check("O:BAG:SYD:P(A;;FRFX;;;BU)", true, false).unwrap();
        }

        #[test]
        fn null_and_absent_dacl_are_rejected() {
            for descriptor in ["O:BAG:SYD:NO_ACCESS_CONTROL", "O:BAG:SY"] {
                let error = check(descriptor, false, false).unwrap_err();
                assert!(error.contains("DACL"), "{error}");
            }
        }

        #[test]
        fn writable_owner_is_rejected_even_with_read_only_dacl() {
            let error = check("O:BUG:SYD:P(A;;FRFX;;;BU)", true, false).unwrap_err();
            assert!(error.contains("владелец"), "{error}");
        }

        #[test]
        fn engine_root_requires_protected_dacl_but_descendants_can_inherit() {
            let inherited = "O:BAG:SYD:(A;ID;FA;;;BA)(A;ID;FRFX;;;BU)";
            assert!(check(inherited, true, false).is_err());
            check(inherited, false, false).unwrap();
        }

        #[test]
        fn engine_rejects_untrusted_inherit_only_write_grants() {
            let descriptor = "O:BAG:SYD:P(A;;FA;;;BA)(A;OICIIO;GA;;;BU)";
            assert!(check(descriptor, true, false).is_err());
            // It grants nothing on an installed ancestor itself. Every actual
            // child on the installed executable path is checked independently.
            check(descriptor, false, true).unwrap();
            assert!(check("O:BAG:SYD:P(A;CI;GA;;;BU)", false, true).is_err());
        }

        #[test]
        fn trustedinstaller_is_allowed_only_for_installed_app_owner() {
            let sid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
            let descriptor = format!("O:{sid}G:SYD:P(A;;FA;;;{sid})(A;;FRFX;;;BU)");
            check(&descriptor, false, true).unwrap();
            assert!(check(&descriptor, false, false).is_err());
            // TrustedInstaller can maintain protected engine files, but cannot
            // be used to trust arbitrary service SIDs or unrelated owners.
            let grant = format!("O:BAG:SYD:P(A;;FA;;;{sid})");
            check(&grant, true, false).unwrap();
            assert!(check("O:BAG:SYD:P(A;;FA;;;S-1-5-80-123)", true, false).is_err());
        }

        #[test]
        fn known_program_files_acl_is_accepted_read_only() {
            let program_files = crate::diagnostics::program_files_dir().unwrap();
            let program_files = program_files.canonicalize().unwrap();
            check_descriptor_impl(&program_files, false, true).unwrap();
        }
    }
}

#[cfg(windows)]
pub(crate) use windows_impl::{
    prepare_engine_storage, verify_engine_storage, verify_protected_path,
};

#[cfg(not(windows))]
pub(crate) fn prepare_engine_storage() -> Result<PathBuf, AppError> {
    Err(AppError::new(
        "windows_only",
        "Защищённое хранилище доступно только в Windows.",
        "Запустите приложение в Windows.",
    ))
}

#[cfg(not(windows))]
pub(crate) fn verify_engine_storage() -> Result<(), AppError> {
    Err(AppError::new(
        "windows_only",
        "Проверка хранилища доступна только в Windows.",
        "Запустите приложение в Windows.",
    ))
}

#[cfg(not(windows))]
pub(crate) fn verify_protected_path(_path: &Path) -> Result<(), AppError> {
    Err(AppError::new(
        "windows_only",
        "Проверка защищённого файла доступна только в Windows.",
        "Запустите приложение в Windows.",
    ))
}

#[cfg(test)]
mod tests {
    use super::{mask_grants_write, ENGINE_ACL_SDDL};

    #[test]
    fn engine_sddl_is_protected_and_grants_users_read_only() {
        assert!(ENGINE_ACL_SDDL.starts_with("O:BA G:SY D:P"));
        assert!(ENGINE_ACL_SDDL.contains("(A;OICI;FA;;;SY)"));
        assert!(ENGINE_ACL_SDDL.contains("(A;OICI;FA;;;BA)"));
        assert!(ENGINE_ACL_SDDL.contains("(A;OICI;GRGX;;;BU)"));
        assert!(!ENGINE_ACL_SDDL.contains(";GW;"));
        assert!(!ENGINE_ACL_SDDL.contains(";GA;"));
    }

    #[test]
    fn write_mask_classifier_rejects_mutating_rights_but_allows_read_execute() {
        assert!(!mask_grants_write(0x0010_0089)); // Read data, attributes, synchronize.
        assert!(!mask_grants_write(0x0000_0020)); // FILE_EXECUTE.
        assert!(mask_grants_write(0x0000_0002)); // FILE_WRITE_DATA.
        assert!(mask_grants_write(0x0004_0000)); // WRITE_DAC.
        assert!(mask_grants_write(0x1000_0000)); // GENERIC_ALL.
    }
}
