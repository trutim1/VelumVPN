//! Local per-application rule editor. Saving rules NEVER changes OS routing.
//! Until a verified dataplane exists, a non-off rule set blocks connect.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tauri::Manager;
use zeroize::Zeroizing;

const MAX_RULES: usize = 128;
const MAX_STORED: u64 = 256 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationMode {
    #[default]
    Off,
    Include,
    Exclude,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SelectedApplication {
    // Stable path identifier, NOT a content hash, signature or immutable
    // executable identity. A future dataplane must validate its own app policy.
    pub id: String,
    pub name: String,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRules {
    pub schema_version: u8,
    pub mode: ApplicationMode,
    pub applications: Vec<SelectedApplication>,
}
impl Default for ApplicationRules {
    fn default() -> Self {
        Self {
            schema_version: 1,
            mode: ApplicationMode::Off,
            applications: vec![],
        }
    }
}

fn validate_shape(rules: &ApplicationRules) -> Result<(), String> {
    if rules.schema_version != 1 || rules.applications.len() > MAX_RULES {
        return Err("Некорректная версия или слишком много приложений".into());
    }
    if rules.mode != ApplicationMode::Off && rules.applications.is_empty() {
        return Err("Добавьте хотя бы одно приложение".into());
    }
    let mut paths = std::collections::HashSet::new();
    for app in &rules.applications {
        if !local_exe_path(&app.path)
            || app.name.trim().is_empty()
            || app.name.len() > 512
            || app.name.chars().any(char::is_control)
            || app.id.len() != 64
            || !app.id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !paths.insert(app.path.to_lowercase())
        {
            return Err("Некорректная или повторная запись приложения".into());
        }
    }
    Ok(())
}

fn local_exe_path(path: &str) -> bool {
    local_path(path) && path.len() > 7 && path.to_ascii_lowercase().ends_with(".exe")
}

fn local_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes.len() < 32_768
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !path[2..].contains([':', '<', '>', '"', '|', '?', '*'])
        && !path.chars().any(char::is_control)
        && !path.contains('/')
        && (path.len() == 3
            || path[3..].split('\\').all(|part| {
                !part.is_empty() && !part.ends_with(['.', ' ']) && !reserved_dos_component(part)
            }))
}

fn reserved_dos_component(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

#[cfg(windows)]
fn verified_handle_path(file: &File, expected: &Path) -> Result<String, String> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(
            handle: *mut c_void,
            path: *mut u16,
            size: u32,
            flags: u32,
        ) -> u32;
    }
    let mut buffer = vec![0u16; 32_768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("Не удалось подтвердить локальный путь".into());
    }
    let final_path =
        String::from_utf16(&buffer[..length]).map_err(|_| "Некорректный локальный путь")?;
    let final_path = final_path
        .strip_prefix(r"\\?\")
        .ok_or("Специальные пути запрещены")?;
    if !local_path(final_path)
        || expected
            .to_str()
            .is_none_or(|path| path.to_lowercase() != final_path.to_lowercase())
    {
        return Err("Путь изменился или содержит перенаправление".into());
    }
    Ok(final_path.to_string())
}

#[cfg(windows)]
fn pin_parents(path: &Path, create: bool) -> Result<Option<Vec<File>>, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    if !path.to_str().is_some_and(local_path) {
        return Err("Требуется однозначный локальный путь".into());
    }
    let mut parents: Vec<_> = path
        .parent()
        .ok_or("Хранилище недоступно")?
        .ancestors()
        .collect();
    parents.reverse();
    let mut held = Vec::with_capacity(parents.len());
    for parent in parents {
        // OPEN_REPARSE_POINT | BACKUP_SEMANTICS; omit FILE_SHARE_DELETE to pin
        // each ancestor before traversing its child. Never canonicalize first.
        let directory = match OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(parent)
        {
            Ok(file) => file,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(parent).map_err(|_| "Не удалось подготовить локальный каталог")?;
                OpenOptions::new()
                    .read(true)
                    .share_mode(3)
                    .custom_flags(0x0220_0000)
                    .open(parent)
                    .map_err(|_| "Локальный каталог недоступен")?
            }
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(_) => return Err("Локальный каталог недоступен".into()),
        };
        let metadata = directory
            .metadata()
            .map_err(|_| "Локальный каталог недоступен")?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err("Ссылки и перенаправления каталогов запрещены".into());
        }
        verified_handle_path(&directory, parent)?;
        held.push(directory);
    }
    Ok(Some(held))
}

#[cfg(not(windows))]
fn pin_parents(_path: &Path, _create: bool) -> Result<Option<Vec<File>>, String> {
    Err("Правила приложений пока доступны только в Windows".into())
}

fn open_regular(path: &Path) -> Result<Option<File>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x0020_0000);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Не удалось открыть локальный файл".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "Не удалось проверить локальный файл")?;
    if !metadata.is_file() {
        return Err("Требуется обычный локальный файл".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Ссылки на файлы запрещены".into());
        }
        verified_handle_path(&file, path)?;
    }
    Ok(Some(file))
}

#[cfg(windows)]
fn inspect_application(path: &Path) -> Result<SelectedApplication, String> {
    let input = path.to_str().ok_or("Некорректный путь приложения")?;
    if !local_exe_path(input) {
        return Err("Выберите локальный файл .exe".into());
    }
    let _parents = pin_parents(path, false)?.ok_or("Приложение недоступно")?;
    let mut file = open_regular(path)?.ok_or("Приложение недоступно")?;
    let normalized = verified_handle_path(&file, path)?;
    if !local_exe_path(&normalized) {
        return Err("Сетевые и специальные пути запрещены".into());
    }
    let metadata = file.metadata().map_err(|_| "Приложение недоступно")?;
    if !metadata.is_file() || metadata.len() < 68 {
        return Err("Это не исполняемый файл Windows".into());
    }
    let mut header = [0u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| "Не удалось проверить приложение")?;
    let offset = u32::from_le_bytes(header[60..64].try_into().unwrap()) as u64;
    if &header[..2] != b"MZ" || !(64..=1024 * 1024).contains(&offset) || offset + 4 > metadata.len()
    {
        return Err("Это не исполняемый файл Windows".into());
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| "Не удалось проверить приложение")?;
    let mut signature = [0u8; 4];
    file.read_exact(&mut signature)
        .map_err(|_| "Не удалось проверить приложение")?;
    if signature != *b"PE\0\0" {
        return Err("Это не исполняемый файл Windows".into());
    }
    let name = Path::new(&normalized)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("Некорректное имя приложения")?
        .to_owned();
    Ok(SelectedApplication {
        id: format!("{:x}", Sha256::digest(normalized.to_lowercase().as_bytes())),
        name,
        path: normalized,
    })
}

#[cfg(not(windows))]
fn inspect_application(_path: &Path) -> Result<SelectedApplication, String> {
    Err("Выбор .exe доступен только в Windows".into())
}

#[tauri::command]
pub fn select_application(
    window: tauri::WebviewWindow,
) -> Result<Option<SelectedApplication>, String> {
    #[cfg(windows)]
    {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};
        use windows_sys::Win32::UI::Controls::Dialogs::*;
        let owner = window.hwnd().map_err(|_| "Окно выбора недоступно")?;
        let filter: Vec<u16> = "Windows application (*.exe)\0*.exe\0\0"
            .encode_utf16()
            .collect();
        let title: Vec<u16> = "Velum — select application\0".encode_utf16().collect();
        let mut path = vec![0u16; 32_768];
        let mut dialog = OPENFILENAMEW {
            lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
            hwndOwner: owner.0,
            lpstrFilter: filter.as_ptr(),
            nFilterIndex: 1,
            lpstrFile: path.as_mut_ptr(),
            nMaxFile: path.len() as u32,
            lpstrTitle: title.as_ptr(),
            Flags: OFN_EXPLORER
                | OFN_FILEMUSTEXIST
                | OFN_PATHMUSTEXIST
                | OFN_NOCHANGEDIR
                | OFN_DONTADDTORECENT
                | OFN_HIDEREADONLY,
            ..Default::default()
        };
        if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
            return if unsafe { CommDlgExtendedError() } == 0 {
                Ok(None)
            } else {
                Err("Окно выбора приложения недоступно".into())
            };
        }
        let length = path
            .iter()
            .position(|value| *value == 0)
            .filter(|value| *value > 0)
            .ok_or("Некорректный путь приложения")?;
        inspect_application(&PathBuf::from(OsString::from_wide(&path[..length]))).map(Some)
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        Err("Выбор .exe доступен только в Windows".into())
    }
}

fn storage_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|_| "Хранилище недоступно")?
        .join("application-rules.dpapi"))
}

#[tauri::command]
pub fn load_application_rules(app: tauri::AppHandle) -> Result<ApplicationRules, String> {
    load_rules(&app)
}

pub fn load_rules(app: &tauri::AppHandle) -> Result<ApplicationRules, String> {
    let path = storage_path(app)?;
    load_rules_at(&path)
}

fn load_rules_at(path: &Path) -> Result<ApplicationRules, String> {
    let Some(_parents) = pin_parents(path, false)? else {
        return Ok(ApplicationRules::default());
    };
    let Some(file) = open_regular(path)? else {
        return Ok(ApplicationRules::default());
    };
    let mut encrypted = Vec::new();
    file.take(MAX_STORED + 1)
        .read_to_end(&mut encrypted)
        .map_err(|_| "Не удалось прочитать правила приложений")?;
    if encrypted.is_empty() || encrypted.len() > MAX_STORED as usize {
        return Err("Некорректный размер правил".into());
    }
    let clear = Zeroizing::new(super::unprotect_secret(&encrypted)?);
    if clear.is_empty() || clear.len() > MAX_STORED as usize {
        return Err("Некорректный размер расшифрованных правил".into());
    }
    let rules: ApplicationRules =
        serde_json::from_slice(&clear).map_err(|_| "Правила приложений повреждены")?;
    validate_shape(&rules)?;
    Ok(rules)
}

fn serialize_rules(rules: &ApplicationRules) -> Result<Zeroizing<Vec<u8>>, String> {
    let clear =
        Zeroizing::new(serde_json::to_vec(rules).map_err(|_| "Не удалось сохранить правила")?);
    if clear.len() > MAX_STORED as usize {
        return Err("Список приложений слишком большой".into());
    }
    Ok(clear)
}

fn prepare_rules(mut rules: ApplicationRules) -> Result<ApplicationRules, String> {
    validate_shape(&rules)?;
    // Off is an explicit recovery path even after an application was removed
    // or changed. Do not inspect executables or silently erase valid selections.
    if rules.mode != ApplicationMode::Off {
        for selected in &mut rules.applications {
            *selected = inspect_application(Path::new(&selected.path))?;
        }
    }
    validate_shape(&rules)?;
    Ok(rules)
}

struct PendingRulesFile {
    path: Option<PathBuf>,
    file: Option<File>,
}

impl Drop for PendingRulesFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

impl PendingRulesFile {
    fn create(directory: &Path) -> Result<Self, String> {
        use std::{
            sync::atomic::{AtomicU64, Ordering},
            time::{SystemTime, UNIX_EPOCH},
        };
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Системное время недоступно")?
            .as_nanos();
        // create_new is the security boundary; freshness avoids an old crashed
        // process's PID-named file permanently preventing Off/recovery saves.
        for _ in 0..8 {
            let path = directory.join(format!(
                ".application-rules-{}-{stamp}-{}.tmp",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.share_mode(0).custom_flags(0x0020_0000);
            }
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path: Some(path),
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("Не удалось создать временный файл правил".into()),
            }
        }
        Err("Не удалось зарезервировать временный файл правил".into())
    }

    fn publish(mut self, path: &Path, encrypted: &[u8]) -> Result<(), String> {
        let file = self.file.as_mut().ok_or("Временный файл недоступен")?;
        file.write_all(encrypted)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Не удалось записать защищённые правила")?;
        drop(self.file.take());
        fs::rename(self.path.as_ref().ok_or("Временный файл недоступен")?, path)
            .map_err(|_| "Не удалось атомарно сохранить правила")?;
        self.path = None;
        Ok(())
    }
}

fn save_rules_at(path: &Path, rules: ApplicationRules) -> Result<ApplicationRules, String> {
    let rules = prepare_rules(rules)?;
    let clear = serialize_rules(&rules)?;
    let protected = super::protect_secret(&clear)?;
    if protected.is_empty() || protected.len() > MAX_STORED as usize {
        return Err("Список приложений слишком большой".into());
    }
    let _parents = pin_parents(path, true)?.ok_or("Хранилище недоступно")?;
    // Reject existing links/directories instead of treating them as a rule
    // store. Drop the read handle before the deliberate atomic replacement.
    drop(open_regular(path)?);
    let directory = path.parent().ok_or("Хранилище недоступно")?;
    PendingRulesFile::create(directory)?.publish(path, &protected)?;
    Ok(rules)
}

#[tauri::command]
pub fn save_application_rules(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, super::Runtime>,
    rules: ApplicationRules,
) -> Result<ApplicationRules, String> {
    let data = app
        .path()
        .app_data_dir()
        .map_err(|_| "Хранилище недоступно")?;
    let _operation = super::PendingOperationLock::acquire(&data)?;
    if super::load_pending_marker(&data)?.is_some() {
        return Err("Сначала отключите туннель".into());
    }
    let state = runtime
        .0
        .lock()
        .map_err(|_| "Состояние туннеля недоступно")?;
    if state.profile.is_some() {
        return Err("Сначала отключите туннель".into());
    }
    let path = storage_path(&app)?;
    let rules = save_rules_at(&path, rules)?;
    drop(state);
    Ok(rules)
}

pub fn require_supported_rules(app: &tauri::AppHandle) -> Result<(), String> {
    require_supported_rule_set(&load_rules(app)?)
}

fn require_supported_rule_set(rules: &ApplicationRules) -> Result<(), String> {
    if rules.mode != ApplicationMode::Off {
        return Err("Правила приложений сохранены, но сетевой адаптер ещё не проверен: подключение заблокировано".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    struct Fixture(PathBuf);

    #[cfg(windows)]
    impl Fixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "velum-rule-test-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn store(&self) -> PathBuf {
            self.0.join("application-rules.dpapi")
        }

        fn application(&self) -> SelectedApplication {
            let path = self.0.join("synthetic.exe");
            let mut bytes = vec![0u8; 68];
            bytes[..2].copy_from_slice(b"MZ");
            bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
            bytes[64..].copy_from_slice(b"PE\0\0");
            fs::write(&path, bytes).unwrap();
            inspect_application(&path).unwrap()
        }

        fn names(&self) -> std::collections::BTreeSet<std::ffi::OsString> {
            fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect()
        }
    }

    #[cfg(windows)]
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only this uniquely created synthetic fixture is ever removed.
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn oversized_serialized_rules_are_rejected_before_any_storage_write() {
        let applications = (0..128)
            .map(|index| SelectedApplication {
                id: format!("{index:064x}"),
                name: "synthetic.exe".into(),
                path: format!("C:\\{}\\{index}.exe", "x".repeat(2021)),
            })
            .collect();
        let rules = ApplicationRules {
            applications,
            ..Default::default()
        };
        assert!(validate_shape(&rules).is_ok());
        assert!(serialize_rules(&rules).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn validates_pe_header_without_executing_selected_file() {
        let fixture = Fixture::new();
        let path = fixture.0.join("synthetic.exe");
        let mut bytes = vec![0u8; 68];
        fs::write(&path, &bytes).unwrap();
        assert!(inspect_application(&path).is_err());
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        fs::write(&path, &bytes).unwrap();
        let selected = inspect_application(&path).unwrap();
        assert_eq!(selected.name, "synthetic.exe");
        assert_eq!(selected.id.len(), 64);
    }
    #[test]
    fn rejects_remote_device_ads_traversal_and_non_exe_paths() {
        for path in [
            r"\\server\app.exe",
            r"\\?\C:\app.exe",
            r"C:\app.exe:stream",
            r"C:\..\app.exe",
            "C:/app.exe",
            "relative.exe",
            "C:\\file.conf",
            "C:\\bad\n.exe",
            r"C:\apps.\app.exe",
            r"C:\apps \app.exe",
            r"C:\apps\\app.exe",
            r"C:\NUL.exe",
            r"C:\COM1\app.exe",
            r"C:\LPT²\app.exe",
            r"C:\CONOUT$.exe",
            r"C:\wild?card.exe",
            r"C:\wild*card.exe",
        ] {
            assert!(!local_exe_path(path), "unsafe path accepted");
        }
        assert!(local_exe_path(r"C:\Program Files\Browser\browser.exe"));
    }
    #[test]
    fn rejects_empty_active_and_duplicate_rules() {
        assert!(validate_shape(&ApplicationRules::default()).is_ok());
        let mut rules = ApplicationRules {
            mode: ApplicationMode::Include,
            ..Default::default()
        };
        assert!(validate_shape(&rules).is_err());
        let selected = SelectedApplication {
            id: "a".repeat(64),
            name: "app.exe".into(),
            path: r"C:\apps\app.exe".into(),
        };
        rules.applications.push(selected.clone());
        assert!(validate_shape(&rules).is_ok());
        rules.applications.push(selected);
        assert!(validate_shape(&rules).is_err());
        rules.applications[1].path = r"c:\APPS\APP.EXE".into();
        assert!(validate_shape(&rules).is_err());
        rules.applications.pop();
        rules.applications[0].name = "   ".into();
        assert!(validate_shape(&rules).is_err());
    }
    #[test]
    fn rejects_unrecognised_serialized_modes_and_fields() {
        assert!(
            serde_json::from_str::<ApplicationRules>(
                r#"{"schema_version":1,"mode":"permit_all","applications":[]}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ApplicationRules>(
                r#"{"schema_version":1,"mode":"off","applications":[],"enforced":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn draft_modes_cannot_be_mistaken_for_enforced_routing() {
        assert!(require_supported_rule_set(&ApplicationRules::default()).is_ok());
        for mode in [ApplicationMode::Include, ApplicationMode::Exclude] {
            let rules = ApplicationRules {
                mode,
                ..Default::default()
            };
            assert!(require_supported_rule_set(&rules).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn snapshot_blocks_file_mutation_and_parent_rename_until_validation_finishes() {
        let fixture = Fixture::new();
        let selected = fixture.application();
        let path = Path::new(&selected.path);
        let parents = pin_parents(path, false).unwrap().unwrap();
        let file = open_regular(path).unwrap().unwrap();
        assert!(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .is_err()
        );
        assert!(fs::rename(path, fixture.0.join("moved.exe")).is_err());
        assert!(fs::rename(&fixture.0, fixture.0.with_extension("moved")).is_err());
        assert!(verified_handle_path(&file, &fixture.0.join("other.exe")).is_err());
        assert_eq!(verified_handle_path(&file, path).unwrap(), selected.path);
        drop(file);
        drop(parents);
        fs::write(path, b"modified after inspection").unwrap();
        assert!(inspect_application(path).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn active_save_rechecks_changed_executable_but_off_retains_valid_draft() {
        let fixture = Fixture::new();
        let selected = fixture.application();
        let mut rules = ApplicationRules {
            mode: ApplicationMode::Include,
            applications: vec![selected.clone()],
            ..Default::default()
        };
        fs::write(&selected.path, b"changed executable after picker").unwrap();
        assert!(save_rules_at(&fixture.store(), rules.clone()).is_err());
        assert!(!fixture.store().exists());
        rules.mode = ApplicationMode::Off;
        assert_eq!(
            save_rules_at(&fixture.store(), rules.clone()).unwrap(),
            rules
        );
        assert_eq!(load_rules_at(&fixture.store()).unwrap(), rules);
        fs::remove_file(&selected.path).unwrap();
        assert_eq!(
            save_rules_at(&fixture.store(), rules.clone()).unwrap(),
            rules
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip_preserves_draft_and_never_enables_adapter() {
        let fixture = Fixture::new();
        let selected = fixture.application();
        let rules = ApplicationRules {
            mode: ApplicationMode::Exclude,
            applications: vec![selected],
            ..Default::default()
        };
        assert_eq!(
            save_rules_at(&fixture.store(), rules.clone()).unwrap(),
            rules
        );
        let encrypted = fs::read(fixture.store()).unwrap();
        let plain = serialize_rules(&rules).unwrap();
        assert_ne!(encrypted, *plain);
        assert!(
            !encrypted
                .windows(b"synthetic.exe".len())
                .any(|chunk| chunk == b"synthetic.exe")
        );
        let loaded = load_rules_at(&fixture.store()).unwrap();
        assert_eq!(loaded, rules);
        assert!(require_supported_rule_set(&loaded).is_err());
        assert_eq!(fixture.names().len(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn corrupt_missing_empty_and_oversized_storage_never_silently_become_off() {
        let fixture = Fixture::new();
        assert_eq!(
            load_rules_at(&fixture.store()).unwrap(),
            ApplicationRules::default()
        );
        for bytes in [
            vec![],
            b"synthetic-invalid-cipher".to_vec(),
            vec![1u8; MAX_STORED as usize + 1],
        ] {
            fs::write(fixture.store(), bytes).unwrap();
            assert!(load_rules_at(&fixture.store()).is_err());
            save_rules_at(&fixture.store(), ApplicationRules::default()).unwrap();
            assert_eq!(
                load_rules_at(&fixture.store()).unwrap(),
                ApplicationRules::default()
            );
        }
        let mut encrypted = fs::read(fixture.store()).unwrap();
        let middle = encrypted.len() / 2;
        encrypted[middle] ^= 0x80;
        fs::write(fixture.store(), encrypted).unwrap();
        assert!(load_rules_at(&fixture.store()).is_err());
        save_rules_at(&fixture.store(), ApplicationRules::default()).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn authenticated_invalid_payloads_are_rejected_without_content_in_errors() {
        let fixture = Fixture::new();
        for payload in [
            b"SYNTHETIC_PRIVATE_ERROR_SENTINEL".as_slice(),
            br#"{"schema_version":2,"mode":"off","applications":[]}"#.as_slice(),
            br#"{"schema_version":1,"mode":"include","applications":[]}"#.as_slice(),
            br#"{"schema_version":1,"mode":"off","applications":[],"enforced":true}"#.as_slice(),
        ] {
            fs::write(
                fixture.store(),
                super::super::protect_secret(payload).unwrap(),
            )
            .unwrap();
            let error = load_rules_at(&fixture.store()).unwrap_err();
            assert!(!error.contains("SYNTHETIC_PRIVATE_ERROR_SENTINEL"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn stale_pid_residue_does_not_block_off_save_or_get_deleted() {
        let fixture = Fixture::new();
        let residue = fixture
            .0
            .join(format!(".application-rules-{}.tmp", std::process::id()));
        fs::write(&residue, b"preserve-unowned-old-residue").unwrap();
        save_rules_at(&fixture.store(), ApplicationRules::default()).unwrap();
        assert_eq!(fs::read(residue).unwrap(), b"preserve-unowned-old-residue");
        assert_eq!(fixture.names().len(), 2);
        assert_eq!(
            load_rules_at(&fixture.store()).unwrap(),
            ApplicationRules::default()
        );
    }

    #[cfg(windows)]
    #[test]
    fn failed_atomic_replace_preserves_previous_cipher_and_cleans_owned_temporary() {
        let fixture = Fixture::new();
        let selected = fixture.application();
        save_rules_at(&fixture.store(), ApplicationRules::default()).unwrap();
        let before = fs::read(fixture.store()).unwrap();
        let names = fixture.names();
        let locked = open_regular(&fixture.store()).unwrap().unwrap();
        let rules = ApplicationRules {
            mode: ApplicationMode::Include,
            applications: vec![selected],
            ..Default::default()
        };
        assert!(save_rules_at(&fixture.store(), rules.clone()).is_err());
        assert_eq!(fs::read(fixture.store()).unwrap(), before);
        assert_eq!(fixture.names(), names);
        drop(locked);
        assert_eq!(
            save_rules_at(&fixture.store(), rules.clone()).unwrap(),
            rules
        );
    }

    #[cfg(windows)]
    #[test]
    fn bounded_save_does_not_create_storage_or_damage_previous_rules() {
        let fixture = Fixture::new();
        let mut rules = ApplicationRules::default();
        for index in 0..128 {
            rules.applications.push(SelectedApplication {
                id: format!("{index:064x}"),
                name: "synthetic.exe".into(),
                path: format!("C:\\{}\\{index}.exe", "x".repeat(2021)),
            });
        }
        let missing = fixture
            .0
            .join("must-stay-missing")
            .join("application-rules.dpapi");
        assert!(save_rules_at(&missing, rules.clone()).is_err());
        assert!(!missing.parent().unwrap().exists());
        save_rules_at(&fixture.store(), ApplicationRules::default()).unwrap();
        let before = fs::read(fixture.store()).unwrap();
        assert!(save_rules_at(&fixture.store(), rules).is_err());
        assert_eq!(fs::read(fixture.store()).unwrap(), before);
        assert_eq!(fixture.names().len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_overhead_cannot_bypass_ciphertext_limit_or_replace_old_rules() {
        let fixture = Fixture::new();
        save_rules_at(&fixture.store(), ApplicationRules::default()).unwrap();
        let before = fs::read(fixture.store()).unwrap();
        let mut rules = ApplicationRules::default();
        for index in 0..9 {
            rules.applications.push(SelectedApplication {
                id: format!("{index:064x}"),
                name: "synthetic.exe".into(),
                path: format!(r"C:\synthetic{index}.exe"),
            });
        }
        let mut remaining = MAX_STORED as usize - 1 - serialize_rules(&rules).unwrap().len();
        for application in &mut rules.applications {
            let extra = remaining.min(32_767 - application.path.len());
            application.path.insert_str(3, &"x".repeat(extra));
            remaining -= extra;
        }
        assert_eq!(remaining, 0);
        validate_shape(&rules).unwrap();
        let clear = serialize_rules(&rules).unwrap();
        assert_eq!(clear.len(), MAX_STORED as usize - 1);
        assert!(super::super::protect_secret(&clear).unwrap().len() > MAX_STORED as usize);
        assert!(save_rules_at(&fixture.store(), rules).is_err());
        assert_eq!(fs::read(fixture.store()).unwrap(), before);
        assert_eq!(fixture.names().len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn directory_at_store_path_is_rejected_without_replacing_its_contents() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.store()).unwrap();
        let sentinel = fixture.store().join("must-preserve.txt");
        fs::write(&sentinel, b"synthetic-preserve").unwrap();
        assert!(load_rules_at(&fixture.store()).is_err());
        assert!(save_rules_at(&fixture.store(), ApplicationRules::default()).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"synthetic-preserve");
        assert_eq!(fixture.names().len(), 1);
    }

    #[cfg(windows)]
    fn create_junction(link: &Path, target: &Path) {
        use std::{
            ffi::c_void,
            os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        };
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn DeviceIoControl(
                handle: *mut c_void,
                code: u32,
                input: *const c_void,
                input_size: u32,
                output: *mut c_void,
                output_size: u32,
                returned: *mut u32,
                overlapped: *mut c_void,
            ) -> i32;
        }
        fs::create_dir(link).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x0220_0000)
            .open(link)
            .unwrap();
        let substitute: Vec<_> = format!(r"\??\{}", target.display())
            .encode_utf16()
            .chain([0])
            .collect();
        let display: Vec<_> = target.to_str().unwrap().encode_utf16().chain([0]).collect();
        let mut data = vec![0u8; 16 + 2 * (substitute.len() + display.len())];
        data[..4].copy_from_slice(&0xA000_0003u32.to_le_bytes());
        let length = (data.len() - 8) as u16;
        data[4..6].copy_from_slice(&length.to_le_bytes());
        data[10..12].copy_from_slice(&((substitute.len() - 1) as u16 * 2).to_le_bytes());
        data[12..14].copy_from_slice(&(substitute.len() as u16 * 2).to_le_bytes());
        data[14..16].copy_from_slice(&((display.len() - 1) as u16 * 2).to_le_bytes());
        for (index, value) in substitute.iter().chain(display.iter()).enumerate() {
            data[16 + index * 2..18 + index * 2].copy_from_slice(&value.to_le_bytes());
        }
        let mut returned = 0;
        assert_ne!(
            unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    0x0009_00A4,
                    data.as_ptr().cast(),
                    data.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }

    #[cfg(windows)]
    #[test]
    fn real_junctions_cannot_redirect_picker_or_rule_storage() {
        let fixture = Fixture::new();
        let outside = Fixture::new();
        outside.application();
        save_rules_at(&outside.store(), ApplicationRules::default()).unwrap();
        let before = fs::read(outside.store()).unwrap();
        let link = fixture.0.join("junction");
        create_junction(&link, &outside.0);
        assert!(inspect_application(&link.join("synthetic.exe")).is_err());
        let redirected_store = link.join("application-rules.dpapi");
        assert!(load_rules_at(&redirected_store).is_err());
        assert!(save_rules_at(&redirected_store, ApplicationRules::default()).is_err());
        assert_eq!(fs::read(outside.store()).unwrap(), before);
        assert_eq!(outside.names().len(), 2);
        fs::remove_dir(link).unwrap();
    }
}
