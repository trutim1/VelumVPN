#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
};
use tauri::{Manager, State};
use vpn_anon_core::{
    amnezia_share::decode_amnezia_share,
    config::{AwgProfile, ProfileSummary},
    protocol::{ProtocolDescriptor, ProtocolId, inspect_protocol_config, protocol_catalog},
    split::{Platform, SplitPolicy},
};
use zeroize::{Zeroize, Zeroizing};

mod app_selection;
mod backend_observation;
mod native_import;
mod profile_store;

use profile_store::write_new_profile;

#[derive(Default)]
struct Runtime(Mutex<TunnelStatus>);

#[derive(Default, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    AwaitingVerification,
    Disconnecting,
    Error,
}

#[derive(Default, Clone, Serialize)]
struct TunnelStatus {
    state: ConnectionState,
    profile: Option<String>,
    message: Option<String>,
    platform: String,
    backend_trusted: bool,
}

#[derive(Serialize)]
struct StoredProfile {
    name: String,
    protocol: ProtocolId,
    summary: ProfileSummary,
}

const MAX_PROTECTED_PROFILE: usize = native_import::MAX_IMPORTED_PROFILE + 16 * 1024;
const PENDING_MARKER_NAME: &str = "pending-tunnel";
const MAX_PENDING_MARKER: u64 = 16 * 1024;
const PENDING_MESSAGE: &str = "Есть незавершённая VPN-операция. Состояние сервиса, маршрутов и защиты не подтверждено; сначала явно отключите туннель";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingTunnel {
    schema_version: u8,
    name: String,
}

fn pending_marker_path(directory: &Path) -> PathBuf {
    directory.join(format!("{PENDING_MARKER_NAME}.dpapi"))
}

struct PendingOperationLock {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "CreateMutexW"]
    fn create_pending_mutex(
        attributes: *const std::ffi::c_void,
        owner: i32,
        name: *const u16,
    ) -> windows_sys::Win32::Foundation::HANDLE;
    #[link_name = "WaitForSingleObject"]
    fn wait_pending_mutex(handle: windows_sys::Win32::Foundation::HANDLE, milliseconds: u32)
    -> u32;
    #[link_name = "ReleaseMutex"]
    fn release_pending_mutex(handle: windows_sys::Win32::Foundation::HANDLE) -> i32;
}

impl PendingOperationLock {
    fn acquire(directory: &Path) -> Result<Self, String> {
        #[cfg(windows)]
        {
            // Current-user AppData determines the scope; this is synchronization,
            // not an authority check. Pre-created/inaccessible objects fail closed.
            let scope = format!(
                "{:x}",
                Sha256::digest(
                    directory
                        .as_os_str()
                        .to_string_lossy()
                        .to_lowercase()
                        .as_bytes()
                )
            );
            // Local\\ is session-specific: two logon sessions of the same user
            // share AppData and must not race save-rules against connect.
            // Creating a Global mutex (unlike a file mapping) needs no
            // SeCreateGlobalPrivilege; inaccessible/precreated objects fail closed.
            let name: Vec<u16> = format!("Global\\Velum.PendingOperation.{scope}\0")
                .encode_utf16()
                .collect();
            let handle = unsafe { create_pending_mutex(std::ptr::null(), 0, name.as_ptr()) };
            if handle.is_null() {
                return Err("Блокировка VPN-операции недоступна".into());
            }
            let result = unsafe { wait_pending_mutex(handle, 5000) };
            if result != 0 && result != 0x80 {
                // WAIT_OBJECT_0 / WAIT_ABANDONED
                unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
                return Err("Другая VPN-операция выполняется или блокировка недоступна".into());
            }
            Ok(Self { handle })
        }
        #[cfg(not(windows))]
        {
            let _ = directory;
            Err("Восстановление VPN-операций пока поддерживается только в Windows".into())
        }
    }
}

impl Drop for PendingOperationLock {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            release_pending_mutex(self.handle);
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

fn load_pending_marker(directory: &Path) -> Result<Option<String>, String> {
    let invalid = "Запись незавершённой VPN-операции повреждена или недоступна. Подключение заблокировано; состояние сервиса не подтверждено";
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x0020_0000); // OPEN_REPARSE_POINT
    }
    let file = match options.open(pending_marker_path(directory)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid.into()),
    };
    let metadata = file.metadata().map_err(|_| invalid)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid.into());
        }
    }
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PENDING_MARKER {
        return Err(invalid.into());
    }
    let mut encrypted = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PENDING_MARKER + 1)
        .read_to_end(&mut encrypted)
        .map_err(|_| invalid)?;
    if encrypted.len() as u64 != metadata.len() || encrypted.len() as u64 > MAX_PENDING_MARKER {
        return Err(invalid.into());
    }
    let clear = Zeroizing::new(unprotect_secret(&encrypted).map_err(|_| invalid)?);
    let pending: PendingTunnel = serde_json::from_slice(&clear).map_err(|_| invalid)?;
    if pending.schema_version != 1 || profile_store::safe_profile_name(&pending.name).is_err() {
        return Err(invalid.into());
    }
    Ok(Some(pending.name))
}

fn write_pending_marker(directory: &Path, name: &str) -> Result<(), String> {
    let pending = PendingTunnel {
        schema_version: 1,
        name: profile_store::safe_profile_name(name)?,
    };
    let clear = Zeroizing::new(
        serde_json::to_vec(&pending).map_err(|_| "Не удалось сохранить запись VPN-операции")?,
    );
    let encrypted = protect_secret(&clear)?;
    // Shared create-new publication makes a second application instance fail
    // before starting another helper; no profile keys are included in this marker.
    write_new_profile(directory, PENDING_MARKER_NAME, &encrypted)
        .map_err(|_| "Не удалось сохранить запись VPN-операции; подключение заблокировано".into())
}

fn restore_pending_state(state: &mut TunnelStatus, pending: Result<Option<String>, String>) {
    match pending {
        Ok(Some(name)) => {
            state.state = ConnectionState::AwaitingVerification;
            state.profile = Some(name);
            state.message = Some(PENDING_MESSAGE.into());
        }
        Err(error) => {
            state.state = ConnectionState::Error;
            state.profile = None;
            state.message = Some(error);
        }
        Ok(None) => {}
    }
}

fn finish_confirmed_cleanup(
    directory: &Path,
    name: &str,
    remove_result: Result<(), String>,
) -> Result<(), String> {
    // The pinned helper's successful removal contract is Stopped + SCM gone +
    // encrypted config removed. Any process/timeout/ACL error preserves the marker.
    remove_result?;
    match load_pending_marker(directory)? {
        Some(pending) if pending == name => std::fs::remove_file(pending_marker_path(directory))
            .map_err(|_| "Сервис удалён, но запись VPN-операции не удалось очистить".into()),
        None => Ok(()),
        Some(_) => Err(
            "Запись VPN-операции относится к другому туннелю; автоматическая очистка запрещена"
                .into(),
        ),
    }
}

#[tauri::command]
fn list_protocols() -> Vec<ProtocolDescriptor> {
    protocol_catalog()
}

#[tauri::command]
fn import_profile_file(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<Option<StoredProfile>, String> {
    let Some(path) = native_import::select_file(&window)? else {
        return Ok(None);
    };
    let source = native_import::read_selected_file(&path)?;
    let name = native_import::profile_name(&path);
    if source.starts_with(b"vpn://") {
        let decoded = decode_amnezia_share(&source).map_err(
            |_| "Профиль Amnezia отклонён: нужен корректный ключ только для подключения",
        )?;
        return store_clear_profile(&app, &name, decoded.expose_config()).map(Some);
    }
    let text = std::str::from_utf8(&source).map_err(|_| "Профиль содержит некорректный UTF-8")?;
    store_clear_profile(&app, &name, text).map(Some)
}

fn store_clear_profile(
    app: &tauri::AppHandle,
    name: &str,
    text: &str,
) -> Result<StoredProfile, String> {
    let safe_name = safe_tunnel_name(name)?;
    let parsed = AwgProfile::parse(text).map_err(|_| "Профиль WireGuard/AmneziaWG отклонён")?;
    let protocol = inspect_protocol_config(&safe_name, text)
        .map_err(|_| "Протокол профиля не поддерживается")?
        .protocol;
    let directory = profiles_dir(app).map_err(|_| "Хранилище профилей недоступно")?;
    std::fs::create_dir_all(&directory).map_err(|_| "Не удалось открыть хранилище профилей")?;
    let protected = protect_secret(text.as_bytes()).map_err(|_| "Не удалось защитить профиль")?;
    write_new_profile(&directory, &safe_name, &protected)?;
    Ok(StoredProfile {
        name: safe_name,
        protocol,
        summary: parsed.summary(),
    })
}

#[tauri::command]
fn list_profiles(app: tauri::AppHandle) -> Result<Vec<StoredProfile>, String> {
    let directory = profiles_dir(&app)?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut profiles = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|v| v.to_str()) != Some("dpapi") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|v| v.to_str())
            .ok_or("Некорректное имя профиля")?
            .to_string();
        let name = safe_tunnel_name(&name)?;
        let protected = read_limited(&path, MAX_PROTECTED_PROFILE)?;
        let clear = Zeroizing::new(unprotect_secret(&protected)?);
        let text =
            std::str::from_utf8(&clear).map_err(|_| "Профиль содержит некорректный UTF-8")?;
        let summary = AwgProfile::parse(text)
            .map_err(|e| e.to_string())?
            .summary();
        let protocol = inspect_protocol_config(&name, text)
            .map_err(|error| error.to_string())?
            .protocol;
        profiles.push(StoredProfile {
            name,
            protocol,
            summary,
        });
    }
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(profiles)
}

fn load_profile(app: &tauri::AppHandle, name: &str) -> Result<Zeroizing<String>, String> {
    let safe_name = safe_tunnel_name(name)?;
    let protected = read_limited(
        &profiles_dir(app)?.join(format!("{safe_name}.dpapi")),
        MAX_PROTECTED_PROFILE,
    )?;
    let clear = unprotect_secret(&protected)?;
    match String::from_utf8(clear) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err("Профиль содержит некорректный UTF-8".into())
        }
    }
}

#[tauri::command]
fn tunnel_status(app: tauri::AppHandle, runtime: State<'_, Runtime>) -> TunnelStatus {
    let mut state = runtime.0.lock().expect("runtime lock");
    if state.profile.is_none() {
        let pending = app
            .path()
            .app_data_dir()
            .map_err(|_| "Хранилище VPN недоступно; состояние сервиса не подтверждено".to_string())
            .and_then(|directory| load_pending_marker(&directory));
        restore_pending_state(&mut state, pending);
    }
    let mut value = state.clone();
    drop(state);
    value.platform = std::env::consts::OS.to_string();
    value.backend_trusted = driver_command().is_some();
    value
}

#[tauri::command]
async fn inspect_tunnel(app: tauri::AppHandle) -> Result<backend_observation::Observation, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "Хранилище VPN недоступно")?;
    tauri::async_runtime::spawn_blocking(move || {
        // Serialize with connect/disconnect across instances. No browser-supplied
        // service name or arbitrary executable is accepted by this read-only path.
        let _operation = PendingOperationLock::acquire(&directory)?;
        let name = load_pending_marker(&directory)?
            .ok_or("Нет незавершённой VPN-операции для проверки")?;
        let driver = required_driver()?;
        let mut command = Command::new(driver);
        command.arg("/status").arg(&name);
        let output = bounded_helper_output_with_timeout(
            &mut command,
            None,
            std::time::Duration::from_secs(5),
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "Системное время недоступно")?
            .as_secs();
        backend_observation::parse(&output, &name, now)
    })
    .await
    .map_err(|_| "Проверка состояния службы прервана")?
}

#[tauri::command]
fn connect_tunnel(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
    name: String,
    policy: SplitPolicy,
) -> Result<(), String> {
    let platform = current_platform()?;
    policy.validate(platform).map_err(|e| e.to_string())?;
    if matches!(policy.mode, vpn_anon_core::split::SplitMode::BypassSelected) {
        return Err("Режим исключений требует платформенного firewall enforcement и пока заблокирован во избежание утечки; используйте «Только выбранное»".into());
    }
    let safe_name = safe_tunnel_name(&name)?;
    let driver = required_driver()?;
    let data = app
        .path()
        .app_data_dir()
        .map_err(|_| "Хранилище VPN недоступно")?;
    let _operation = PendingOperationLock::acquire(&data)?;
    {
        let mut state = runtime.0.lock().map_err(|_| "runtime lock")?;
        if matches!(
            state.state,
            ConnectionState::Connecting
                | ConnectionState::AwaitingVerification
                | ConnectionState::Disconnecting
        ) || state.profile.is_some()
        {
            return Err("Другой VPN-переход уже выполняется или туннель активен".into());
        }
        let pending = load_pending_marker(&data);
        if !matches!(pending, Ok(None)) {
            restore_pending_state(&mut state, pending);
            return Err(state
                .message
                .clone()
                .unwrap_or_else(|| PENDING_MESSAGE.into()));
        }
        // Held under the same lock as save_application_rules: a non-off draft
        // cannot race this check and be silently bypassed during connection.
        app_selection::require_supported_rules(&app)?;
        state.state = ConnectionState::Connecting;
        state.profile = Some(safe_name.clone());
        state.message = None;
    }
    let mut pending_registered = false;
    let result = (|| {
        let text = load_profile(&app, &safe_name)?;
        AwgProfile::parse(&text).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&data).map_err(|e| e.to_string())?;
        let effective = effective_config(&text, &policy)?;
        validate_helper_input(effective.as_bytes())?;
        write_pending_marker(&data, &safe_name)?;
        pending_registered = true;
        platform_up(&driver, &safe_name, effective)
    })();
    let mut state = runtime.0.lock().map_err(|_| "runtime lock")?;
    match result {
        Ok(()) => {
            state.state = ConnectionState::AwaitingVerification;
            state.message = Some("Сервис принял конфигурацию. Маршруты, DNS и отсутствие утечек ещё не проверены; защита не подтверждена".into());
            Ok(())
        }
        Err(error) => {
            state.state = ConnectionState::Error;
            // A helper may have partially installed the service before failing.
            // Retain the exact identity so an explicit disconnect can clean it up.
            if !pending_registered {
                state.profile = None;
            }
            state.message = Some(error.clone());
            Err(error)
        }
    }
}

#[tauri::command]
fn disconnect_tunnel(app: tauri::AppHandle, runtime: State<'_, Runtime>) -> Result<(), String> {
    let data = app
        .path()
        .app_data_dir()
        .map_err(|_| "Хранилище VPN недоступно")?;
    let _operation = PendingOperationLock::acquire(&data)?;
    let safe_name = {
        let mut state = runtime.0.lock().map_err(|_| "runtime lock")?;
        if matches!(
            state.state,
            ConnectionState::Connecting | ConnectionState::Disconnecting
        ) {
            return Err("VPN-переход уже выполняется".into());
        }
        let active = state.profile.clone().ok_or("Нет активного туннеля")?;
        if load_pending_marker(&data)?.as_deref() != Some(active.as_str()) {
            return Err("Запись VPN-операции отсутствует или не совпадает; автоматическое отключение заблокировано".into());
        }
        state.state = ConnectionState::Disconnecting;
        state.message = None;
        active
    };
    let result = finish_confirmed_cleanup(&data, &safe_name, platform_down(&safe_name));
    let mut state = runtime.0.lock().map_err(|_| "runtime lock")?;
    match result {
        Ok(()) => {
            state.state = ConnectionState::Disconnected;
            state.profile = None;
            state.message = None;
            Ok(())
        }
        Err(error) => {
            state.state = ConnectionState::Error;
            state.profile = Some(safe_name);
            state.message = Some(error.clone());
            Err(error)
        }
    }
}

fn safe_tunnel_name(name: &str) -> Result<String, String> {
    profile_store::safe_profile_name(name)
}
fn profiles_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("profiles"))
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let expected = file.metadata().map_err(|e| e.to_string())?.len();
    if expected == 0 || expected > limit as u64 {
        return Err("Защищённый профиль пуст или превышает безопасный лимит".into());
    }
    let mut bytes = Vec::with_capacity(expected as usize);
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != expected || bytes.len() > limit {
        bytes.zeroize();
        return Err("Размер защищённого профиля изменился во время чтения".into());
    }
    Ok(bytes)
}

#[cfg(windows)]
fn protect_secret(input: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    let source = CRYPT_INTEGER_BLOB {
        cbData: input
            .len()
            .try_into()
            .map_err(|_| "Профиль слишком большой")?,
        pbData: input.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptProtectData(
            &source,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!(
            "DPAPI encryption failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(result)
}

#[cfg(windows)]
fn unprotect_secret(input: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    let source = CRYPT_INTEGER_BLOB {
        cbData: input
            .len()
            .try_into()
            .map_err(|_| "Профиль слишком большой")?,
        pbData: input.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptUnprotectData(
            &source,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!(
            "DPAPI decryption failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    for offset in 0..output.cbData as usize {
        unsafe { output.pbData.add(offset).write_volatile(0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(result)
}

#[cfg(not(windows))]
fn protect_secret(_input: &[u8]) -> Result<Vec<u8>, String> {
    Err("Защищённое постоянное хранилище пока реализовано только через Windows DPAPI".into())
}
#[cfg(not(windows))]
fn unprotect_secret(_input: &[u8]) -> Result<Vec<u8>, String> {
    Err("Защищённое постоянное хранилище пока реализовано только через Windows DPAPI".into())
}

fn current_platform() -> Result<Platform, String> {
    match std::env::consts::OS {
        "windows" => Ok(Platform::Windows),
        "linux" => Ok(Platform::Linux),
        "macos" => Ok(Platform::MacOs),
        other => Err(format!(
            "Платформа {other} требует нативного мобильного адаптера"
        )),
    }
}
fn driver_command() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        return [PathBuf::from(
            r"C:\Program Files\Velum VPN\bin\velum-awg.exe",
        )]
        .into_iter()
        .find(|path| trusted_windows_backend(path));
    }
    #[cfg(target_os = "linux")]
    {
        return [
            PathBuf::from("/usr/libexec/velum/velum-awg-quick"),
            PathBuf::from("/usr/local/libexec/velum/velum-awg-quick"),
        ]
        .into_iter()
        .find(|path| trusted_root_helper(path));
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(windows)]
const TRUSTED_WINDOWS_BACKEND_SHA256: &[[u8; 32]] = &[];

#[cfg(windows)]
fn trusted_windows_backend(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match std::io::Read::read(&mut file, &mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => return false,
        };
        hash.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hash.finalize().into();
    TRUSTED_WINDOWS_BACKEND_SHA256.contains(&digest)
}

#[cfg(target_os = "linux")]
fn trusted_root_helper(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    path.metadata().is_ok_and(|metadata| {
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
    })
}

fn required_driver() -> Result<PathBuf, String> {
    driver_command().ok_or_else(|| if cfg!(windows) { "Подписанный модуль Velum AWG не установлен. Внешние исполняемые файлы Amnezia и пути из окружения намеренно не используются".to_string() } else { "Доверенный root-owned модуль Velum AWG не установлен".to_string() })
}

fn platform_up(driver: &Path, name: &str, mut config: Zeroizing<String>) -> Result<(), String> {
    if cfg!(windows) {
        let mut command = Command::new(driver);
        command.arg("/installtunnelstdin").arg(name);
        // Move the existing allocation into the writer; do not clone plaintext
        // into argv, logs, another unprotected buffer or a staging file.
        let input = Zeroizing::new(std::mem::take(&mut *config).into_bytes());
        let output = bounded_helper_output(&mut command, Some(input))?;
        return validate_install_ack(&output, name);
    }
    Err(
        "Безопасная передача конфигурации системному модулю пока поддерживается только в Windows"
            .into(),
    )
}

const MAX_HELPER_ACK: usize = 16 * 1024;
const MAX_HELPER_INPUT: usize = 256 * 1024;

fn validate_helper_input(input: &[u8]) -> Result<(), String> {
    if input.is_empty() || input.len() > MAX_HELPER_INPUT {
        return Err("Конфигурация пуста или превышает безопасный лимит 256 KiB".into());
    }
    Ok(())
}

#[derive(Deserialize)]
struct InstallAck {
    schema_version: u16,
    name: String,
    config_accepted: bool,
    service_state: String,
    tunnel_ready: bool,
    traffic_verified: bool,
}

fn validate_install_ack(bytes: &[u8], expected_name: &str) -> Result<(), String> {
    let invalid =
        "Системный модуль не подтвердил принятие конфигурации; состояние туннеля не подтверждено";
    if bytes.is_empty() || bytes.len() > MAX_HELPER_ACK {
        return Err(invalid.into());
    }
    let ack: InstallAck = serde_json::from_slice(bytes).map_err(|_| invalid)?;
    if ack.schema_version != 1
        || ack.name != expected_name
        || !ack.config_accepted
        || ack.service_state != "running"
        || ack.tunnel_ready
        || ack.traffic_verified
    {
        // A new protocol claiming verification is not silently trusted. This
        // version has no leak-proof verifier; Running alone is never Connected.
        return Err(invalid.into());
    }
    Ok(())
}

struct RunningHelper(std::process::Child);

impl Drop for RunningHelper {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn bounded_helper_output(
    command: &mut Command,
    input: Option<Zeroizing<Vec<u8>>>,
) -> Result<Vec<u8>, String> {
    bounded_helper_output_with_timeout(command, input, std::time::Duration::from_secs(120))
}

fn bounded_helper_output_with_timeout(
    command: &mut Command,
    input: Option<Zeroizing<Vec<u8>>>,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, String> {
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };
    if let Some(bytes) = &input {
        validate_helper_input(bytes)?;
    }
    let mut child = RunningHelper(
        command
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Не удалось запустить системный AWG")?,
    );
    let write_receiver = input.map(|bytes| {
        let mut stdin = child.0.stdin.take().expect("piped stdin configured");
        let (sender, receiver) = mpsc::channel();
        // A blocking pipe writer never owns the parent timeout loop. Killing the
        // helper closes the read end, unblocking the writer on cancellation.
        std::thread::spawn(move || {
            let result = stdin
                .write_all(&bytes)
                .and_then(|_| stdin.flush())
                .map_err(|_| ());
            drop(stdin); // EOF is mandatory before the helper accepts the snapshot.
            drop(bytes); // Zeroize the owned plaintext allocation before acknowledgement.
            let _ = sender.send(result);
        });
        receiver
    });
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or("Ответ системного AWG недоступен")?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take((MAX_HELPER_ACK + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
            .map_err(|_| ());
        let _ = sender.send(result);
    });
    let started = Instant::now();
    let mut write_complete = write_receiver.is_none();
    loop {
        if !write_complete {
            match write_receiver.as_ref().expect("writer exists").try_recv() {
                Ok(Ok(())) => write_complete = true,
                Ok(Err(())) | Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("Не удалось передать конфигурацию системному AWG".into());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        match child.0.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(
                        "Системный AWG не завершил операцию; состояние туннеля не подтверждено"
                            .into(),
                    );
                }
                if !write_complete {
                    write_receiver
                        .as_ref()
                        .expect("writer exists")
                        .recv_timeout(Duration::from_secs(1))
                        .map_err(|_| "Передача конфигурации не подтверждена")?
                        .map_err(|_| "Не удалось передать конфигурацию системному AWG")?;
                }
                let bytes = receiver
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| "Ответ системного AWG не получен")?
                    .map_err(|_| "Ответ системного AWG не прочитан")?;
                if bytes.len() > MAX_HELPER_ACK {
                    return Err("Ответ системного AWG превышает безопасный лимит".into());
                }
                return Ok(bytes);
            }
            Err(_) => {
                return Err("Состояние системного AWG не подтверждено".into());
            }
            Ok(None) => {}
        }
        if started.elapsed() >= timeout {
            let _ = child.0.kill();
            let _ = child.0.wait();
            if !write_complete {
                // The killed helper closes its anonymous-pipe read handle. Wait
                // briefly for the writer to zeroize its allocation before return.
                let _ = write_receiver
                    .as_ref()
                    .expect("writer exists")
                    .recv_timeout(Duration::from_secs(1));
            }
            return Err(
                "Системный AWG не ответил вовремя; состояние туннеля не подтверждено".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn platform_down(name: &str) -> Result<(), String> {
    let driver = driver_command().ok_or_else(|| "Системный AWG-драйвер не найден".to_string())?;
    if cfg!(windows) {
        let mut command = Command::new(driver);
        command.arg("/uninstalltunnelservice").arg(name);
        let output = bounded_helper_output(&mut command, None)?;
        if !output.is_empty() {
            return Err(
                "Неожиданное подтверждение удаления системного AWG; состояние не подтверждено"
                    .into(),
            );
        }
        return Ok(());
    }
    Err("Системное управление туннелем пока поддерживается только в Windows".into())
}

fn effective_config(source: &str, policy: &SplitPolicy) -> Result<Zeroizing<String>, String> {
    policy
        .validate_supported()
        .map_err(|error| error.to_string())?;
    if matches!(policy.mode, vpn_anon_core::split::SplitMode::ProfileRoutes) {
        return Ok(Zeroizing::new(source.to_string()));
    }
    if AwgProfile::parse(source)
        .map_err(|_| "Профиль WireGuard/AmneziaWG отклонён")?
        .peers
        .len()
        != 1
    {
        return Err("Выбор сетей поддерживается только для профиля с одним Peer; распределение маршрутов между Peer не реализовано".into());
    }
    let routes = policy
        .networks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut in_peer = false;
    let mut replaced = false;
    let mut output = Zeroizing::new(String::new());
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_peer = trimmed.eq_ignore_ascii_case("[Peer]");
        }
        if in_peer
            && trimmed
                .split_once('=')
                .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("AllowedIPs"))
        {
            output.push_str("AllowedIPs = ");
            output.push_str(&routes);
            replaced = true;
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    if !replaced {
        return Err("В конфигурации не найден Peer.AllowedIPs".into());
    }
    Ok(output)
}
fn main() {
    tauri::Builder::default()
        .manage(Runtime::default())
        .setup(|app| {
            let pending = app
                .path()
                .app_data_dir()
                .map_err(|_| {
                    "Хранилище VPN недоступно; состояние сервиса не подтверждено".to_string()
                })
                .and_then(|directory| load_pending_marker(&directory));
            let runtime = app.state::<Runtime>();
            if let Ok(mut state) = runtime.0.lock() {
                restore_pending_state(&mut state, pending);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_protocols,
            import_profile_file,
            list_profiles,
            tunnel_status,
            inspect_tunnel,
            connect_tunnel,
            disconnect_tunnel,
            app_selection::select_application,
            app_selection::load_application_rules,
            app_selection::save_application_rules
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Velum");
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_anon_core::split::SplitMode;

    #[test]
    fn synthetic_helper_child() {
        let Ok(mode) = std::env::var("VELUM_SYNTHETIC_STDIO_CHILD") else {
            return;
        };
        match mode.as_str() {
            "read" => {
                let mut input = Zeroizing::new(Vec::new());
                std::io::stdin()
                    .take((MAX_HELPER_INPUT + 1) as u64)
                    .read_to_end(&mut input)
                    .unwrap();
                println!("synthetic-length={}", input.len());
                drop(input);
            }
            "oversized-output" => {
                std::io::stdout()
                    .write_all(&vec![b'x'; MAX_HELPER_ACK + 1])
                    .unwrap();
            }
            "reject" => std::process::exit(13),
            "stall" => std::thread::sleep(std::time::Duration::from_secs(30)),
            #[cfg(windows)]
            "close-input" => {
                use std::os::windows::io::AsRawHandle;
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(std::io::stdin().as_raw_handle());
                }
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
            _ => std::process::exit(14),
        }
        std::io::stdout().flush().unwrap();
        std::process::exit(0);
    }

    fn synthetic_helper(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "tests::synthetic_helper_child",
                "--nocapture",
                "--quiet",
            ])
            .env("VELUM_SYNTHETIC_STDIO_CHILD", mode);
        command
    }

    #[test]
    fn helper_stdin_is_bounded_before_spawn_and_accepts_exact_limit_with_eof() {
        for size in [0, MAX_HELPER_INPUT + 1] {
            let mut absent_executable = Command::new("velum-synthetic-must-not-be-spawned");
            let error = bounded_helper_output_with_timeout(
                &mut absent_executable,
                Some(Zeroizing::new(vec![b'x'; size])),
                std::time::Duration::from_secs(2),
            )
            .unwrap_err();
            assert!(error.contains("256 KiB"));
        }
        let output = bounded_helper_output_with_timeout(
            &mut synthetic_helper("read"),
            Some(Zeroizing::new(vec![b'x'; MAX_HELPER_INPUT])),
            std::time::Duration::from_secs(10),
        )
        .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("synthetic-length=262144")
        );
    }

    #[test]
    fn helper_errors_and_oversized_output_are_redacted() {
        let marker = b"synthetic-plaintext-never-print";
        let error = bounded_helper_output_with_timeout(
            &mut synthetic_helper("reject"),
            Some(Zeroizing::new(marker.to_vec())),
            std::time::Duration::from_secs(10),
        )
        .unwrap_err();
        assert!(!error.contains("synthetic-plaintext-never-print"));
        assert!(
            bounded_helper_output_with_timeout(
                &mut synthetic_helper("oversized-output"),
                None,
                std::time::Duration::from_secs(10)
            )
            .is_err()
        );
    }

    #[test]
    fn helper_timeout_cancels_a_blocked_stdin_writer_without_waiting_for_child_sleep() {
        let started = std::time::Instant::now();
        let error = bounded_helper_output_with_timeout(
            &mut synthetic_helper("stall"),
            Some(Zeroizing::new(vec![b'x'; MAX_HELPER_INPUT])),
            std::time::Duration::from_millis(700),
        )
        .unwrap_err();
        assert!(error.contains("не ответил вовремя"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[cfg(windows)]
    #[test]
    fn helper_stdin_failure_cancels_the_still_running_child() {
        let started = std::time::Instant::now();
        let error = bounded_helper_output_with_timeout(
            &mut synthetic_helper("close-input"),
            Some(Zeroizing::new(vec![b'x'; MAX_HELPER_INPUT])),
            std::time::Duration::from_secs(10),
        )
        .unwrap_err();
        assert!(error.contains("передать конфигурацию"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[cfg(windows)]
    fn pending_test_directory() -> PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "velum-pending-test-{}-{timestamp}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        directory
    }

    #[cfg(windows)]
    #[test]
    fn restart_restores_uncertain_state_and_only_confirmed_cleanup_removes_marker() {
        let directory = pending_test_directory();
        write_pending_marker(&directory, "synthetic").unwrap();
        assert!(write_pending_marker(&directory, "different").is_err());
        let encrypted = std::fs::read(pending_marker_path(&directory)).unwrap();
        let clear = Zeroizing::new(unprotect_secret(&encrypted).unwrap());
        let marker: serde_json::Value = serde_json::from_slice(&clear).unwrap();
        assert_eq!(marker.as_object().unwrap().len(), 2);
        assert_eq!(marker["name"], "synthetic");
        let mut restarted = TunnelStatus::default();
        restore_pending_state(&mut restarted, load_pending_marker(&directory));
        assert!(matches!(
            restarted.state,
            ConnectionState::AwaitingVerification
        ));
        assert_eq!(restarted.profile.as_deref(), Some("synthetic"));
        assert!(
            finish_confirmed_cleanup(
                &directory,
                "synthetic",
                Err("synthetic helper failed".into())
            )
            .is_err()
        );
        assert_eq!(
            load_pending_marker(&directory).unwrap().as_deref(),
            Some("synthetic")
        );
        assert!(finish_confirmed_cleanup(&directory, "different", Ok(())).is_err());
        assert!(pending_marker_path(&directory).exists());
        finish_confirmed_cleanup(&directory, "synthetic", Ok(())).unwrap();
        assert!(load_pending_marker(&directory).unwrap().is_none());
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn corrupt_or_oversized_marker_fails_closed_without_echoing_input() {
        let directory = pending_test_directory();
        for bytes in [
            b"synthetic-corrupt-marker".to_vec(),
            vec![b'x'; MAX_PENDING_MARKER as usize + 1],
            protect_secret(br#"{"schema_version":2,"name":"synthetic"}"#).unwrap(),
            protect_secret(br#"{"schema_version":1,"name":"../escape"}"#).unwrap(),
        ] {
            std::fs::write(pending_marker_path(&directory), bytes).unwrap();
            let pending = load_pending_marker(&directory);
            assert!(pending.is_err());
            let mut restarted = TunnelStatus::default();
            restore_pending_state(&mut restarted, pending);
            assert!(matches!(restarted.state, ConnectionState::Error));
            assert!(restarted.profile.is_none());
            assert!(
                !restarted
                    .message
                    .unwrap()
                    .contains("synthetic-corrupt-marker")
            );
            assert!(finish_confirmed_cleanup(&directory, "synthetic", Ok(())).is_err());
            assert!(pending_marker_path(&directory).exists());
        }
        std::fs::remove_file(pending_marker_path(&directory)).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn named_operation_lock_serializes_separate_callers_and_releases_on_drop() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let directory = pending_test_directory();
        let active = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let directory = &directory;
                let active = &active;
                scope.spawn(move || {
                    let _guard = PendingOperationLock::acquire(directory).unwrap();
                    assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                });
            }
        });
        let reacquired = PendingOperationLock::acquire(&directory).unwrap();
        drop(reacquired);
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn helper_install_ack_is_acceptance_not_connection_or_leak_proof() {
        let ack = serde_json::json!({"schema_version":1,"name":"synthetic","config_accepted":true,"service_state":"running","tunnel_ready":false,"traffic_verified":false,"handshake_fresh":true});
        assert!(validate_install_ack(&serde_json::to_vec(&ack).unwrap(), "synthetic").is_ok());
        for (field, replacement) in [
            ("schema_version", serde_json::json!(2)),
            ("name", serde_json::json!("different")),
            ("config_accepted", serde_json::json!(false)),
            ("service_state", serde_json::json!("stopped")),
            ("tunnel_ready", serde_json::json!(true)),
            ("traffic_verified", serde_json::json!(true)),
        ] {
            let mut invalid = ack.clone();
            invalid[field] = replacement;
            assert!(
                validate_install_ack(&serde_json::to_vec(&invalid).unwrap(), "synthetic").is_err(),
                "{field}"
            );
            invalid.as_object_mut().unwrap().remove(field);
            assert!(
                validate_install_ack(&serde_json::to_vec(&invalid).unwrap(), "synthetic").is_err(),
                "missing {field}"
            );
        }
        assert!(validate_install_ack(b"", "synthetic").is_err());
        assert!(validate_install_ack(&vec![b' '; MAX_HELPER_ACK + 1], "synthetic").is_err());
        let error = validate_install_ack(b"private-key-sentinel", "synthetic").unwrap_err();
        assert!(!error.contains("private-key-sentinel"));
        assert_eq!(
            serde_json::to_string(&ConnectionState::AwaitingVerification).unwrap(),
            "\"awaiting_verification\""
        );
    }

    #[test]
    fn profile_routes_preserve_imported_cidrs_and_reject_every_unsupported_rule() {
        let source = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.1:51820\nAllowedIPs = 192.0.2.0/24\n";
        let policy: SplitPolicy = serde_json::from_str(r#"{"mode":"profile_routes"}"#).unwrap();
        assert_eq!(effective_config(source, &policy).unwrap().as_str(), source);
        for mode in [
            "profile_routes",
            "only_selected",
            "bypass_selected",
            "full_tunnel",
        ] {
            for extra in [
                r#""applications":["test.exe"]"#,
                r#""domains":["example.test"]"#,
                r#""bypass_lan":true"#,
            ] {
                let policy: SplitPolicy =
                    serde_json::from_str(&format!(r#"{{"mode":"{mode}",{extra}}}"#)).unwrap();
                assert!(effective_config(source, &policy).is_err());
            }
        }
    }

    #[test]
    fn protected_profile_import_never_overwrites_existing_identity() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("velum-import-test-{}-{unique}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        write_new_profile(&directory, "synthetic", b"first-protected-blob").unwrap();
        let result = write_new_profile(&directory, "synthetic", b"second-protected-blob");
        assert!(result.is_err());
        let destination = directory.join("synthetic.dpapi");
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"first-protected-blob"
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn selected_networks_replace_peer_routes_without_adding_commands() {
        let source = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n";
        let policy = SplitPolicy {
            mode: SplitMode::OnlySelected,
            networks: vec!["10.0.0.0/8".parse().unwrap()],
            domains: vec![],
            applications: vec![],
            bypass_lan: false,
        };
        let effective = effective_config(source, &policy).unwrap();
        assert!(effective.contains("AllowedIPs = 10.0.0.0/8"));
        assert!(!effective.contains("0.0.0.0/0"));
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip_is_user_bound() {
        let secret = b"private-profile-material";
        let protected = protect_secret(secret).unwrap();
        assert_ne!(protected, secret);
        assert_eq!(unprotect_secret(&protected).unwrap(), secret);
    }
}
