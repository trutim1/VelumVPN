#[cfg(not(windows))]
compile_error!("velum-import currently targets Windows DPAPI only");

use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

use vpn_anon_core::{
    amnezia_share::decode_amnezia_share, config::AwgProfile, protocol::inspect_protocol_config,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData},
};
use zeroize::Zeroizing;

#[path = "../profile_store.rs"]
mod profile_store;

const MAX_INPUT: u64 = 256 * 1024;
const USAGE: &str = "Использование: velum-import <name> <source.conf|source.vpn|->";

fn main() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let name = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(USAGE)?;
    let source = arguments
        .next()
        .ok_or("Не указан источник профиля; используйте путь или - для stdin")?;
    if arguments.next().is_some() {
        return Err("Передано слишком много аргументов".into());
    }
    let safe_name = profile_store::safe_profile_name(&name)?;
    let input = read_source(&source)?;
    let clear = if input.starts_with(b"vpn://") {
        let decoded = decode_amnezia_share(&input).map_err(|_| "Amnezia share-профиль отклонён")?;
        Zeroizing::new(decoded.expose_config().to_owned())
    } else {
        Zeroizing::new(
            std::str::from_utf8(&input)
                .map_err(|_| "Профиль содержит некорректный UTF-8")?
                .to_owned(),
        )
    };
    AwgProfile::parse(&clear).map_err(|_| "Профиль WireGuard/AmneziaWG отклонён")?;
    let inspection = inspect_protocol_config(&safe_name, &clear)
        .map_err(|_| "Тип профиля не распознан или профиль отклонён")?;
    let protected = protect(clear.as_bytes())?;

    let app_data = std::env::var_os("APPDATA").ok_or("APPDATA не определён")?;
    let directory = PathBuf::from(app_data)
        .join("ru.anon.velum")
        .join("profiles");
    fs::create_dir_all(&directory).map_err(|_| "Не удалось открыть хранилище профилей")?;
    profile_store::write_new_profile(&directory, &safe_name, &protected)?;
    println!(
        "Импортирован профиль {safe_name} ({:?})",
        inspection.protocol
    );
    Ok(())
}

fn read_source(source: &OsStr) -> Result<Zeroizing<Vec<u8>>, String> {
    if source == OsStr::new("-") {
        let stdin = std::io::stdin();
        return read_bounded(
            stdin.lock(),
            None,
            "Не удалось прочитать исходный профиль из stdin",
        );
    }
    read_profile_file(Path::new(source))
}

fn read_profile_file(source: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let source_file = OpenOptions::new()
        .read(true)
        .open(source)
        .map_err(|_| "Не удалось открыть исходный профиль")?;
    let metadata = source_file
        .metadata()
        .map_err(|_| "Не удалось проверить исходный профиль")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT {
        return Err("Исходный профиль пуст или превышает 256 KiB".into());
    }
    read_bounded(
        source_file,
        Some(metadata.len()),
        "Не удалось прочитать исходный профиль",
    )
}

fn read_bounded<R: Read>(
    mut reader: R,
    expected_len: Option<u64>,
    read_error: &'static str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if expected_len.is_some_and(|length| length == 0 || length > MAX_INPUT) {
        return Err("Исходный профиль пуст или превышает 256 KiB".into());
    }
    let capacity = expected_len.unwrap_or_default() as usize;
    let mut input = Zeroizing::new(Vec::with_capacity(capacity));
    Read::by_ref(&mut reader)
        .take(MAX_INPUT + 1)
        .read_to_end(&mut input)
        .map_err(|_| read_error)?;
    if input.is_empty() || input.len() as u64 > MAX_INPUT {
        return Err("Исходный профиль пуст или превышает 256 KiB".into());
    }
    if expected_len.is_some_and(|length| input.len() as u64 != length) {
        return Err("Исходный профиль изменился во время чтения или превышает 256 KiB".into());
    }
    Ok(input)
}

fn protect(input: &[u8]) -> Result<Vec<u8>, String> {
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn bounded_reader_accepts_raw_stdin_without_expected_length() {
        let input = read_bounded(Cursor::new(b"raw-awg-config"), None, "redacted").unwrap();
        assert_eq!(input.as_slice(), b"raw-awg-config");
    }

    #[test]
    fn bounded_reader_accepts_exact_maximum() {
        let source = vec![b'x'; MAX_INPUT as usize];
        let input = read_bounded(Cursor::new(source), None, "redacted").unwrap();
        assert_eq!(input.len() as u64, MAX_INPUT);
    }

    #[test]
    fn bounded_reader_rejects_empty_and_oversized_streams() {
        assert!(read_bounded(Cursor::new(Vec::<u8>::new()), None, "redacted").is_err());
        let oversized = vec![b'x'; MAX_INPUT as usize + 1];
        assert!(read_bounded(Cursor::new(oversized), None, "redacted").is_err());
    }

    #[test]
    fn bounded_reader_detects_file_length_change() {
        let error = read_bounded(Cursor::new(b"short"), Some(8), "redacted").unwrap_err();
        assert!(error.contains("изменился во время чтения"));
    }
}
