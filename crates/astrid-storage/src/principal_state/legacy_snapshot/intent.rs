//! Opaque captured identities used as durable retirement authorization.

use super::LegacySourceKind;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authorization to retire one captured original source generation.
///
/// The type is opaque: it has no public constructor and stores no paths.
/// Database stage names are derived from the captured generation only.
/// Unknown fields are refused so an old path-only receipt cannot silently
/// become a deletion grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LegacyRetirementIntent(IntentBody);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum IntentBody {
    Empty {
        captured_root: LegacyCapturedIdentity,
    },
    Database {
        captured_root: LegacyCapturedIdentity,
        captured_lock: LegacyCapturedIdentity,
        generation: Uuid,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "platform", rename_all = "snake_case")]
pub(super) enum LegacyCapturedIdentity {
    WindowsDirectory {
        identity: astrid_core::platform_fs::DirectoryIdentity,
    },
    WindowsFile {
        volume: u64,
        file_id: [u8; 16],
    },
    Unix {
        volume: u64,
        inode: u64,
    },
}

impl LegacyRetirementIntent {
    pub(super) fn empty(captured_root: LegacyCapturedIdentity) -> Self {
        Self(IntentBody::Empty { captured_root })
    }

    pub(super) fn database(
        captured_root: LegacyCapturedIdentity,
        captured_lock: LegacyCapturedIdentity,
        generation: Uuid,
    ) -> Self {
        Self(IntentBody::Database {
            captured_root,
            captured_lock,
            generation,
        })
    }

    /// Classification of the source captured by this retirement intent.
    #[must_use]
    pub fn kind(&self) -> LegacySourceKind {
        match self.0 {
            IntentBody::Empty { .. } => LegacySourceKind::EmptyDirectory,
            IntentBody::Database { .. } => LegacySourceKind::LockedDatabase,
        }
    }

    pub(super) fn captured_root(&self) -> &LegacyCapturedIdentity {
        match &self.0 {
            IntentBody::Empty { captured_root } | IntentBody::Database { captured_root, .. } => {
                captured_root
            },
        }
    }

    pub(super) fn captured_lock(&self) -> Option<&LegacyCapturedIdentity> {
        match &self.0 {
            IntentBody::Database { captured_lock, .. } => Some(captured_lock),
            IntentBody::Empty { .. } => None,
        }
    }

    pub(super) fn stage_name(&self) -> Option<String> {
        match &self.0 {
            IntentBody::Database { generation, .. } => Some(format!("legacy-retire-{generation}")),
            IntentBody::Empty { .. } => None,
        }
    }

    pub(super) fn matches_source(
        &self,
        kind: LegacySourceKind,
        captured_root: &LegacyCapturedIdentity,
        captured_lock: Option<&LegacyCapturedIdentity>,
    ) -> bool {
        if self.kind() != kind || self.captured_root() != captured_root {
            return false;
        }
        match (self.captured_lock(), captured_lock) {
            (None, None) => true,
            (Some(expected), Some(actual)) => expected == actual,
            _ => false,
        }
    }
}

impl LegacyCapturedIdentity {
    #[cfg(any(not(windows), test))]
    pub(super) fn from_unix(volume: u64, inode: u64) -> Self {
        Self::Unix { volume, inode }
    }

    #[cfg(windows)]
    pub(super) fn from_windows_file_id(volume: u64, file_id: [u8; 16]) -> Self {
        Self::WindowsFile { volume, file_id }
    }

    #[cfg(windows)]
    pub(super) fn from_windows_directory(
        identity: astrid_core::platform_fs::DirectoryIdentity,
    ) -> Self {
        Self::WindowsDirectory { identity }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_serde_roundtrip_and_unknown_fields_are_denied() {
        let intent = LegacyRetirementIntent::empty(LegacyCapturedIdentity::from_unix(1, 2));
        let encoded = serde_json::to_string(&intent).unwrap();
        let decoded: LegacyRetirementIntent = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, intent);
        assert!(
            serde_json::from_str::<LegacyRetirementIntent>(
                r#"{"kind":"empty","captured_root":{"platform":"unix","volume":1,"inode":2},"extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn matches_source_ignores_generation() {
        let root = LegacyCapturedIdentity::from_unix(3, 4);
        let lock = LegacyCapturedIdentity::from_unix(5, 6);
        let first = LegacyRetirementIntent::database(root.clone(), lock.clone(), Uuid::nil());
        let mut value = serde_json::to_value(&first).unwrap();
        value["generation"] = serde_json::json!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let second: LegacyRetirementIntent = serde_json::from_value(value).unwrap();
        assert_ne!(first, second);
        assert!(second.matches_source(LegacySourceKind::LockedDatabase, &root, Some(&lock)));
    }
}
