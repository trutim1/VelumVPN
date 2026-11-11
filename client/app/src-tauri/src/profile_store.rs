//! Shared GUI/CLI publication boundary for encrypted, immutable profile identities.

use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const EXISTS: &str = "Профиль с этим именем уже существует; перезапись запрещена";
const STORE_ERROR: &str = "Не удалось сохранить защищённый профиль";

pub fn safe_profile_name(name: &str) -> Result<String, String> {
    let valid = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    let upper = name.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'));
    if !valid || reserved {
        return Err("Недопустимое имя профиля".into());
    }
    Ok(name.to_owned())
}

struct PendingProfile(PathBuf);

impl Drop for PendingProfile {
    fn drop(&mut self) {
        // Only the exact file successfully created by this invocation is removed.
        let _ = fs::remove_file(&self.0);
    }
}

pub fn write_new_profile(directory: &Path, name: &str, protected: &[u8]) -> Result<(), String> {
    let name = safe_profile_name(name)?;
    let destination = directory.join(format!("{name}.dpapi"));
    if destination.exists() {
        return Err(EXISTS.into());
    }
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".{name}.{}.{sequence}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(STORE_ERROR.into()),
        };
        let pending = PendingProfile(path);
        // Declare the handle after the cleanup guard so it is closed first on error.
        let mut file = file;
        file.write_all(protected)
            .and_then(|_| file.sync_all())
            .map_err(|_| STORE_ERROR)?;
        drop(file);
        // Unlike rename, hard_link is atomic AND cannot replace an existing name,
        // including when GUI and CLI imports race from different processes.
        fs::hard_link(&pending.0, &destination).map_err(|error| {
            if error.kind() == ErrorKind::AlreadyExists || destination.exists() {
                EXISTS
            } else {
                STORE_ERROR
            }
        })?;
        return Ok(());
    }
    Err(STORE_ERROR.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "velum-store-test-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn simultaneous_imports_publish_exactly_one_complete_identity() {
        let directory = directory();
        let barrier = Arc::new(Barrier::new(12));
        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..12)
                .map(|index| {
                    let barrier = barrier.clone();
                    let directory = &directory;
                    scope.spawn(move || {
                        let bytes = vec![index; 32768];
                        barrier.wait();
                        (
                            index,
                            write_new_profile(directory, "identity", &bytes).is_ok(),
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        let winners: Vec<_> = outcomes
            .into_iter()
            .filter(|(_, success)| *success)
            .collect();
        assert_eq!(winners.len(), 1);
        assert_eq!(
            fs::read(directory.join("identity.dpapi")).unwrap(),
            vec![winners[0].0; 32768]
        );
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        assert!(write_new_profile(&directory, "identity", b"replacement").is_err());
        fs::remove_file(directory.join("identity.dpapi")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn invalid_names_cannot_escape_or_address_windows_devices() {
        for name in [
            "",
            "..",
            "../profile",
            "a/b",
            "a\\b",
            "CON",
            "nul",
            "COM1",
            "Lpt9",
            "profile.conf",
            "имя",
        ] {
            assert!(safe_profile_name(name).is_err(), "{name}");
        }
        assert!(safe_profile_name(&"x".repeat(33)).is_err());
        assert_eq!(safe_profile_name("phone-2_test").unwrap(), "phone-2_test");
    }
}
