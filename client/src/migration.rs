use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    config::{AwgProfile, ConfigError, ProfileSummary},
    split::{SplitError, SplitPolicy},
};

#[derive(Debug, Deserialize)]
pub struct ImportManifest {
    pub schema_version: u16,
    pub users: Vec<ImportUser>,
}

#[derive(Debug, Deserialize)]
pub struct ImportUser {
    pub external_id: String,
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    pub profiles: Vec<ImportProfile>,
}

#[derive(Debug, Deserialize)]
pub struct ImportProfile {
    pub name: String,
    pub config_path: PathBuf,
    #[serde(default)]
    pub split: Option<SplitPolicy>,
}

#[derive(Debug, Serialize)]
pub struct MigrationPlan {
    pub schema_version: u16,
    pub users: Vec<PlannedUser>,
    pub profile_count: usize,
}

#[derive(Debug, Serialize)]
pub struct PlannedUser {
    pub id: Uuid,
    pub external_id: String,
    pub display_name: String,
    pub email: Option<String>,
    pub profiles: Vec<PlannedProfile>,
}

#[derive(Debug, Serialize)]
pub struct PlannedProfile {
    pub id: Uuid,
    pub name: String,
    pub source: PathBuf,
    pub summary: ProfileSummary,
    pub split: Option<SplitPolicy>,
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("invalid migration manifest")]
    Manifest,
    #[error("unsupported migration schema {0}")]
    Schema(u16),
    #[error("duplicate external user id: {0}")]
    DuplicateUser(String),
    #[error("duplicate VPN identity {fingerprint} in {first} and {second}")]
    DuplicateProfile {
        fingerprint: String,
        first: String,
        second: String,
    },
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config {path}: {source}")]
    Config { path: PathBuf, source: ConfigError },
    #[error("profile path escapes the migration directory: {0}")]
    PathEscape(PathBuf),
    #[error("unsupported migration split policy: {0}")]
    Split(#[from] SplitError),
}

impl ImportManifest {
    /// Read a manifest as a bounded, zeroizing buffer. Parser diagnostics are
    /// deliberately not retained because they can echo user-provided values.
    pub fn read_from(path: &Path) -> Result<Self, MigrationError> {
        let bytes =
            crate::migration_input::read_manifest(path).map_err(|source| MigrationError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        serde_json::from_slice(&bytes).map_err(|_| MigrationError::Manifest)
    }

    pub fn plan(self, base: &Path) -> Result<MigrationPlan, MigrationError> {
        if self.schema_version != 1 {
            return Err(MigrationError::Schema(self.schema_version));
        }
        let canonical_base = base.canonicalize().map_err(|source| MigrationError::Read {
            path: base.to_path_buf(),
            source,
        })?;
        let mut user_ids = HashSet::new();
        let mut identities: BTreeMap<String, String> = BTreeMap::new();
        let mut users = Vec::new();
        let mut profile_count = 0;
        for user in self.users {
            if !user_ids.insert(user.external_id.clone()) {
                return Err(MigrationError::DuplicateUser(user.external_id));
            }
            let mut profiles = Vec::new();
            for profile in user.profiles {
                if let Some(policy) = &profile.split {
                    policy.validate_supported()?;
                }
                let bytes =
                    crate::migration_input::read_confined(&canonical_base, &profile.config_path)
                        .map_err(|source_error| MigrationError::Read {
                            path: profile.config_path.clone(),
                            source: source_error,
                        })?;
                let text = std::str::from_utf8(&bytes).map_err(|_| MigrationError::Read {
                    path: profile.config_path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "profile is not valid UTF-8",
                    ),
                })?;
                let parsed =
                    AwgProfile::parse(text).map_err(|source_error| MigrationError::Config {
                        path: profile.config_path.clone(),
                        source: source_error,
                    })?;
                let fingerprint = parsed.fingerprint();
                if let Some(first) =
                    identities.insert(fingerprint.clone(), user.external_id.clone())
                {
                    return Err(MigrationError::DuplicateProfile {
                        fingerprint,
                        first,
                        second: user.external_id,
                    });
                }
                profiles.push(PlannedProfile {
                    id: Uuid::new_v4(),
                    name: profile.name,
                    source: profile.config_path,
                    summary: parsed.summary(),
                    split: profile.split,
                });
                profile_count += 1;
            }
            users.push(PlannedUser {
                id: Uuid::new_v4(),
                external_id: user.external_id,
                display_name: user.display_name,
                email: user.email,
                profiles,
            });
        }
        Ok(MigrationPlan {
            schema_version: 1,
            users,
            profile_count,
        })
    }
}
