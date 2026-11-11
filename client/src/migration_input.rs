//! Bounded secret-bearing reads and handle-anchored migration path traversal.

use std::{
    fs::File,
    io::{self, Read},
    path::{Component, Path},
};
use zeroize::Zeroizing;

pub(crate) const MAX_MANIFEST: u64 = 1024 * 1024;
pub(crate) const MAX_PROFILE: u64 = 256 * 1024;

fn invalid_input() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "input is not a bounded regular file",
    )
}

pub(crate) fn read_bounded(file: File, limit: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err(invalid_input());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err(invalid_input());
    }
    Ok(bytes)
}

pub(crate) fn read_manifest(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1); // FILE_SHARE_READ; hold the same file throughout the read.
    }
    read_bounded(options.open(path)?, MAX_MANIFEST)
}

fn relative_components(path: &Path) -> io::Result<Vec<&std::ffi::OsStr>> {
    let mut result = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(invalid_input());
        };
        // Reject Windows alternate data streams and DOS path normalization aliases,
        // even when a manifest is validated on another operating system.
        let text = name.to_str().ok_or_else(invalid_input)?;
        if text.contains([':', '\\']) || text.ends_with(['.', ' ']) {
            return Err(invalid_input());
        }
        result.push(name);
    }
    if result.is_empty() {
        return Err(invalid_input());
    }
    Ok(result)
}

#[cfg(windows)]
pub(crate) fn read_confined(base: &Path, relative: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::{
        ffi::OsString,
        fs::OpenOptions,
        os::windows::{
            ffi::OsStringExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
    };
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(
            handle: *mut std::ffi::c_void,
            path: *mut u16,
            length: u32,
            flags: u32,
        ) -> u32;
    }
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const REPARSE_POINT: u32 = 0x0400;
    let components = relative_components(relative)?;
    let mut directories = Vec::new();
    let mut path = base.to_path_buf();
    // Every opened directory is retained without FILE_SHARE_WRITE/DELETE until
    // the final single-handle read completes, preventing rename/reparse races.
    for component in components {
        let directory = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
            .open(&path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & REPARSE_POINT != 0 {
            return Err(invalid_input());
        }
        directories.push(directory);
        path.push(component);
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(path)?;
    if file.metadata()?.file_attributes() & REPARSE_POINT != 0 {
        return Err(invalid_input());
    }
    // Verify the path of the opened handle, never a second pathname lookup.
    // This also catches a changed ancestor above the selected base directory.
    let mut resolved = vec![0_u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            resolved.as_mut_ptr(),
            resolved.len() as u32,
            0,
        )
    };
    if length == 0 || length as usize >= resolved.len() {
        return Err(invalid_input());
    }
    let resolved = std::path::PathBuf::from(OsString::from_wide(&resolved[..length as usize]));
    if !resolved.starts_with(base) {
        return Err(invalid_input());
    }
    let result = read_bounded(file, MAX_PROFILE);
    drop(directories);
    result
}

#[cfg(unix)]
pub(crate) fn read_confined(base: &Path, relative: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
    };
    let components = relative_components(relative)?;
    let mut parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(base)?;
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_bytes()).map_err(|_| invalid_input())?;
        let last = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if last {
                libc::O_NONBLOCK
            } else {
                libc::O_DIRECTORY
            };
        // SAFETY: live directory fd, NUL-terminated single component, no O_CREAT.
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned fd, transferred exactly once.
        parent = unsafe { File::from_raw_fd(descriptor) };
    }
    read_bounded(parent, MAX_PROFILE)
}

#[cfg(not(any(windows, unix)))]
pub(crate) fn read_confined(_base: &Path, _relative: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "confined migration reads are unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traversal_absolute_paths_streams_and_device_aliases_are_rejected() {
        for path in [
            "../a",
            "a/../../b",
            "/tmp/a",
            "./a",
            "a:stream",
            "a.",
            "a ",
            "",
        ] {
            assert!(relative_components(Path::new(path)).is_err(), "{path}");
        }
        assert!(relative_components(Path::new("nested/profile.conf")).is_ok());
    }
}
