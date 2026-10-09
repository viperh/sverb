//! Integration tests for `Paths::ensure`.
#![cfg(unix)]

use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

use sverb_core::paths::{DirKind, EnvSource, MapEnv, Paths, SystemEnv};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh, unique temp directory removed on drop.
struct TempHome(PathBuf);

impl TempHome {
    fn new(tag: &str) -> std::io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "sverb-paths-test-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn paths_for(home: &TempHome) -> Result<Paths, Box<dyn std::error::Error>> {
    let mut env = MapEnv::new().var("SVERB_HOME", home.path().as_os_str());
    if let Some(uid) = SystemEnv.uid() {
        env = env.uid(uid);
    }
    Ok(Paths::resolve(&env)?)
}

fn mode(path: &Path) -> std::io::Result<u32> {
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
}

#[test]
fn ensure_creates_private_dirs() -> TestResult {
    let home = TempHome::new("ensure")?;
    let paths = paths_for(&home)?;
    for kind in [DirKind::Config, DirKind::Data, DirKind::State, DirKind::Run] {
        let dir = paths.dir(kind).ok_or("no dir on unix")?;
        assert!(!dir.exists());
        paths.ensure(kind)?;
        assert!(dir.is_dir());
        assert_eq!(mode(dir)?, 0o700, "{kind:?}");
        // Idempotent.
        paths.ensure(kind)?;
    }
    Ok(())
}

#[test]
fn ensure_refuses_loose_runtime_dir() -> TestResult {
    let home = TempHome::new("runtime")?;
    let paths = paths_for(&home)?;
    let run = paths.runtime_dir().ok_or("no runtime dir")?;
    std::fs::DirBuilder::new().mode(0o755).create(run)?;
    std::fs::set_permissions(run, std::fs::Permissions::from_mode(0o755))?;

    let err = paths
        .ensure(DirKind::Run)
        .err()
        .ok_or("loose runtime dir was accepted")?;
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    // The mode was not silently fixed.
    assert_eq!(mode(run)?, 0o755);

    std::fs::set_permissions(run, std::fs::Permissions::from_mode(0o700))?;
    paths.ensure(DirKind::Run)?;
    Ok(())
}

#[test]
fn ensure_refuses_symlinked_runtime_dir() -> TestResult {
    let home = TempHome::new("symlink")?;
    let paths = paths_for(&home)?;
    let target = home.path().join("elsewhere");
    std::fs::DirBuilder::new().mode(0o700).create(&target)?;
    std::os::unix::fs::symlink(&target, paths.runtime_dir().ok_or("no runtime dir")?)?;
    assert!(paths.ensure(DirKind::Run).is_err());
    Ok(())
}

#[test]
fn ensure_only_warns_for_loose_data_dir() -> TestResult {
    let home = TempHome::new("loose-data")?;
    let paths = paths_for(&home)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(paths.data_dir())?;
    std::fs::set_permissions(paths.data_dir(), std::fs::Permissions::from_mode(0o755))?;
    paths.ensure(DirKind::Data)?;
    assert_eq!(mode(paths.data_dir())?, 0o755);
    Ok(())
}

#[test]
fn ensure_does_not_chmod_sverb_home_root() -> TestResult {
    let home = TempHome::new("root")?;
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o755))?;
    let paths = paths_for(&home)?;
    paths.ensure(DirKind::Config)?;
    assert_eq!(mode(home.path())?, 0o755);
    Ok(())
}

#[test]
fn ensure_refuses_runtime_dir_owned_by_someone_else() -> TestResult {
    let home = TempHome::new("owner")?;
    let real_uid = SystemEnv.uid().ok_or("no uid")?;
    let env = MapEnv::new()
        .var("SVERB_HOME", home.path().as_os_str())
        .uid(real_uid.wrapping_add(1));
    let paths = Paths::resolve(&env)?;
    let err = paths
        .ensure(DirKind::Run)
        .err()
        .ok_or("foreign-owned runtime dir was accepted")?;
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    Ok(())
}
