//! Operator-only user execution budgets. Absence preserves personal-install behavior.

use astrid_core::UserUid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU64;

/// Aggregate WASM fuel rates across all principals charged to a user.
/// Cooperative scheduling permits a one-second burst and scheduling-boundary
/// overshoot; excess remains owed and delays further execution. These are not
/// strict per-second instruction ceilings, host CPU billing, or OS process caps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceConfig {
    /// Default fuel/second rate for users without an explicit override.
    /// Omitted means no new aggregate limit; existing principal limits remain.
    pub default_user_cpu_fuel_per_sec: Option<NonZeroU64>,
    /// Per-user aggregate fuel/second rates, indexed by immutable user UID.
    /// Zero is invalid, never an unlimited sentinel.
    pub user_cpu_fuel_per_sec: BTreeMap<UserUid, NonZeroU64>,
}

impl ResourceConfig {
    /// Effective operator allocation for one accountable user.
    #[must_use]
    pub fn cpu_limit(&self, user: UserUid) -> Option<NonZeroU64> {
        self.user_cpu_fuel_per_sec
            .get(&user)
            .copied()
            .or(self.default_user_cpu_fuel_per_sec)
    }

    /// Whether attribution is mandatory to enforce any configured allocation.
    #[must_use]
    pub fn has_cpu_limits(&self) -> bool {
        self.default_user_cpu_fuel_per_sec.is_some() || !self.user_cpu_fuel_per_sec.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_default_is_unchanged_and_zero_is_not_unlimited() {
        assert!(!ResourceConfig::default().has_cpu_limits());
        assert!(toml::from_str::<ResourceConfig>("default_user_cpu_fuel_per_sec = 0").is_err());
        let user = UserUid::from_bytes([1; 32]);
        assert!(
            toml::from_str::<ResourceConfig>(&format!("[user_cpu_fuel_per_sec]\n'{user}' = 0"))
                .is_err()
        );
        let config: ResourceConfig = toml::from_str(&format!(
            "default_user_cpu_fuel_per_sec = 100\n[user_cpu_fuel_per_sec]\n'{user}' = 200"
        ))
        .unwrap();
        assert_eq!(config.cpu_limit(user).unwrap().get(), 200);
        assert_eq!(
            config
                .cpu_limit(UserUid::from_bytes([2; 32]))
                .unwrap()
                .get(),
            100
        );
    }

    #[test]
    fn workspace_cannot_add_remove_or_raise_user_allocations() {
        for baseline in ["", "[resources]\ndefault_user_cpu_fuel_per_sec = 100"] {
            for workspace in [
                "resources = {}",
                "[resources]\ndefault_user_cpu_fuel_per_sec = 999999",
            ] {
                let baseline: toml::Value = toml::from_str(baseline).unwrap();
                let workspace: toml::Value = toml::from_str(workspace).unwrap();
                let mut merged = baseline.clone();
                crate::merge::deep_merge(&mut merged, &workspace);
                crate::merge::enforce_restrictions(&mut merged, &baseline, &workspace);
                assert_eq!(merged.get("resources"), baseline.get("resources"));
            }
        }
    }
}
