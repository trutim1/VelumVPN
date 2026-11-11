use std::fs;
use vpn_anon_core::migration::ImportManifest;

const CONFIG: &str = "[Interface]\nPrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress=10.0.0.2/32\nJc=4\n[Peer]\nPublicKey=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nPresharedKey=AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\nEndpoint=203.0.113.1:1234\nAllowedIPs=0.0.0.0/0\n";

fn manifest(path: &std::path::Path) -> ImportManifest {
    serde_json::from_value(serde_json::json!({"schema_version":1,"users":[{"external_id":"1","display_name":"A","profiles":[{"name":"phone","config_path":path}]}]})).unwrap()
}

#[test]
fn plans_migration_without_private_keys() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.conf"), CONFIG).unwrap();
    let manifest = manifest(std::path::Path::new("a.conf"));
    let json = serde_json::to_string(&manifest.plan(dir.path()).unwrap()).unwrap();
    assert!(!json.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    assert!(!json.contains("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="));
    assert!(json.contains("profile_count"));
}

#[test]
fn nested_regular_profiles_work_but_traversal_absolute_and_nonfiles_fail() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested/a.conf"), CONFIG).unwrap();
    assert!(
        manifest(std::path::Path::new("nested/a.conf"))
            .plan(dir.path())
            .is_ok()
    );
    for path in [
        std::path::PathBuf::from("../outside.conf"),
        dir.path().join("nested/a.conf"),
        "nested".into(),
    ] {
        assert!(manifest(&path).plan(dir.path()).is_err(), "{path:?}");
    }
}

#[test]
fn oversized_or_non_utf8_profiles_and_manifests_are_rejected_without_echoing_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.conf");
    fs::write(&path, vec![b'x'; 256 * 1024 + 1]).unwrap();
    assert!(
        manifest(std::path::Path::new("a.conf"))
            .plan(dir.path())
            .is_err()
    );
    fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(
        manifest(std::path::Path::new("a.conf"))
            .plan(dir.path())
            .is_err()
    );
    let path = dir.path().join("manifest.json");
    fs::write(&path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    assert!(ImportManifest::read_from(&path).is_err());
    fs::write(&path, r#"{"schema_version":"secret-marker","users":[]}"#).unwrap();
    let error = ImportManifest::read_from(&path).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("secret-marker"));
}

#[test]
fn migration_rejects_unsupported_policies_before_reading_profile() {
    let dir = tempfile::tempdir().unwrap();
    let mut input = manifest(std::path::Path::new("a.conf"));
    input.users[0].profiles[0].split = Some(
        serde_json::from_str(r#"{"mode":"full_tunnel","applications":["test.exe"]}"#).unwrap(),
    );
    let error = input.plan(dir.path()).unwrap_err();
    assert!(matches!(
        error,
        vpn_anon_core::migration::MigrationError::Split(_)
    ));
}

#[cfg(windows)]
#[test]
fn directory_junctions_cannot_escape_the_migration_boundary() {
    // Junctions do not require developer mode or elevation (unlike symlinks).
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("a.conf"), CONFIG).unwrap();
    let junction = dir.path().join("linked");
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:VELUM_TEST_JUNCTION -Target $env:VELUM_TEST_TARGET | Out-Null",
        ])
        .env("VELUM_TEST_JUNCTION", &junction)
        .env("VELUM_TEST_TARGET", outside.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        manifest(std::path::Path::new("linked/a.conf"))
            .plan(dir.path())
            .is_err()
    );
    // Remove only the junction itself, never recursively walk its target.
    fs::remove_dir(junction).unwrap();
}

#[cfg(unix)]
#[test]
fn file_and_directory_symlinks_cannot_escape_the_migration_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("a.conf"), CONFIG).unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("a.conf"), dir.path().join("a.conf")).unwrap();
    for path in ["linked/a.conf", "a.conf"] {
        assert!(
            manifest(std::path::Path::new(path))
                .plan(dir.path())
                .is_err()
        );
    }
}
