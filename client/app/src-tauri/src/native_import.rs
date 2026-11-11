use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const MAX_IMPORTED_PROFILE: usize = 256 * 1024;
const READ_ERROR: &str = "Не удалось безопасно прочитать выбранный файл";
const SIZE_ERROR: &str = "Профиль пуст или превышает 256 KiB";
const CHANGED_ERROR: &str = "Файл изменился во время чтения; повторите импорт";

#[cfg(windows)]
pub fn select_file(window: &tauri::WebviewWindow) -> Result<Option<PathBuf>, &'static str> {
    use windows_sys::Win32::UI::Controls::Dialogs::{
        CommDlgExtendedError, GetOpenFileNameW, OFN_DONTADDTORECENT, OFN_EXPLORER,
        OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };

    let owner = window
        .hwnd()
        .map_err(|_| "Не удалось открыть окно выбора файла")?;
    let filter: Vec<u16> = "Профиль VPN (*.conf;*.vpn)\0*.conf;*.vpn\0\0"
        .encode_utf16()
        .collect();
    let title: Vec<u16> = "Импорт профиля Velum\0".encode_utf16().collect();
    let mut path = vec![0_u16; 32_768];
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
    // All pointers belong to live buffers until this synchronous, owner-modal call returns.
    let accepted = unsafe { GetOpenFileNameW(&mut dialog) } != 0;
    let error = if accepted {
        0
    } else {
        unsafe { CommDlgExtendedError() }
    };
    dialog_selection(accepted, error, &path)
}

#[cfg(not(windows))]
pub fn select_file(_window: &tauri::WebviewWindow) -> Result<Option<PathBuf>, &'static str> {
    Err("Нативный импорт и защищённое хранилище пока доступны только в Windows")
}

#[cfg(windows)]
fn dialog_selection(
    accepted: bool,
    error: u32,
    buffer: &[u16],
) -> Result<Option<PathBuf>, &'static str> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    if !accepted {
        return if error == 0 {
            Ok(None)
        } else {
            Err("Не удалось открыть окно выбора файла")
        };
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .filter(|length| *length > 0)
        .ok_or("Окно выбора файла вернуло некорректный путь")?;
    Ok(Some(PathBuf::from(OsString::from_wide(&buffer[..length]))))
}

pub fn read_selected_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let extension = path.extension().and_then(|value| value.to_str());
    if !extension.is_some_and(|value| {
        value.eq_ignore_ascii_case("conf") || value.eq_ignore_ascii_case("vpn")
    }) {
        return Err("Выберите профиль с расширением .conf или .vpn");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ permits concurrent readers, but rejects a writable/deletable handle.
        options.share_mode(1);
    }
    let file = options.open(path).map_err(|_| READ_ERROR)?;
    let metadata = file.metadata().map_err(|_| READ_ERROR)?;
    if !metadata.is_file() {
        return Err(READ_ERROR);
    }
    read_bounded(file, metadata.len())
}

fn read_bounded(source: impl Read, expected: u64) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if expected == 0 || expected > MAX_IMPORTED_PROFILE as u64 {
        return Err(SIZE_ERROR);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(expected as usize));
    source
        .take((MAX_IMPORTED_PROFILE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| READ_ERROR)?;
    if bytes.len() > MAX_IMPORTED_PROFILE {
        return Err(SIZE_ERROR);
    }
    if bytes.len() as u64 != expected {
        return Err(CHANGED_ERROR);
    }
    Ok(bytes)
}

pub fn profile_name(path: &Path) -> String {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let mut name = String::new();
    for character in stem.chars() {
        let safe = if character.is_ascii_alphanumeric() || character == '_' {
            character
        } else {
            '-'
        };
        if safe == '-' && (name.is_empty() || name.ends_with('-')) {
            continue;
        }
        if name.len() == 32 {
            break;
        }
        name.push(safe);
    }
    name.truncate(name.trim_end_matches('-').len());
    if name.is_empty() {
        name.push_str("profile");
    }
    let upper = name.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            upper.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
            })
        });
    if reserved {
        name.insert_str(0, "profile-");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Error, ErrorKind};

    #[test]
    fn accepts_exact_limit_and_rejects_empty_or_large_metadata() {
        let source = vec![b'x'; MAX_IMPORTED_PROFILE];
        assert_eq!(
            read_bounded(Cursor::new(&source), source.len() as u64)
                .unwrap()
                .len(),
            MAX_IMPORTED_PROFILE
        );
        assert_eq!(read_bounded(Cursor::new([]), 0).unwrap_err(), SIZE_ERROR);
        assert_eq!(
            read_bounded(Cursor::new([]), (MAX_IMPORTED_PROFILE + 1) as u64).unwrap_err(),
            SIZE_ERROR
        );
    }

    #[test]
    fn detects_growth_and_shrinkage_without_unbounded_read() {
        assert_eq!(
            read_bounded(Cursor::new(b"x"), 2).unwrap_err(),
            CHANGED_ERROR
        );
        assert_eq!(
            read_bounded(Cursor::new(b"xy"), 1).unwrap_err(),
            CHANGED_ERROR
        );
        let source = vec![b'x'; MAX_IMPORTED_PROFILE + 100];
        let mut cursor = Cursor::new(source);
        assert_eq!(read_bounded(&mut cursor, 1).unwrap_err(), SIZE_ERROR);
        assert_eq!(cursor.position(), (MAX_IMPORTED_PROFILE + 1) as u64);
    }

    #[test]
    fn read_errors_do_not_expose_source_error_text() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "private-config-sentinel",
                ))
            }
        }
        assert_eq!(read_bounded(BrokenReader, 1).unwrap_err(), READ_ERROR);
    }

    #[test]
    fn names_are_bounded_ascii_and_avoid_windows_devices() {
        for (path, expected) in [
            ("profile.conf", "profile"),
            ("My VPN (2).vpn", "My-VPN-2"),
            ("Германия.conf", "profile"),
            ("CON.conf", "profile-CON"),
            ("Lpt9.vpn", "profile-Lpt9"),
        ] {
            assert_eq!(profile_name(Path::new(path)), expected);
        }
        assert_eq!(
            profile_name(Path::new(&format!("{}.conf", "a".repeat(80)))).len(),
            32
        );
    }

    #[cfg(windows)]
    #[test]
    fn cancel_is_normal_but_dialog_failure_is_an_error() {
        assert!(dialog_selection(false, 0, &[]).unwrap().is_none());
        assert!(dialog_selection(false, 1, &[]).is_err());
        assert!(dialog_selection(true, 0, &[]).is_err());
        assert!(dialog_selection(true, 0, &[0]).is_err());
        let path: Vec<u16> = "C:\\synthetic\\profile.conf\0".encode_utf16().collect();
        assert_eq!(
            dialog_selection(true, 0, &path).unwrap(),
            Some(PathBuf::from("C:\\synthetic\\profile.conf"))
        );
    }
}
