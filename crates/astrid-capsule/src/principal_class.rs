//! Bounded principal-class label for telemetry and IPC host-fn audit
//! labels. Used only for emitting bounded-cardinality metrics labels
//! (3 buckets) — dispatcher routing (mpsc queues and `chain_locks`) is
//! now keyed on the unbounded `PrincipalKey` so distinct user
//! principals do not collide on a single class-keyed queue.

/// Three-way classification of an IPC message's originating principal.
/// The mapping mirrors `astrid_events::principal_class_label` so labels
/// across the routing-demux and dispatcher metrics collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrincipalClass {
    /// Kernel-internal / no principal set.
    System,
    /// Authenticated user principal.
    User,
    /// `agent.*` or `agent:*` ephemeral agent.
    Agent,
}

impl PrincipalClass {
    /// Classify by `Option<&str>` principal string.
    #[must_use]
    pub fn from_str_opt(principal: Option<&str>) -> Self {
        match principal {
            None => Self::System,
            Some(p) if p.starts_with("agent.") || p.starts_with("agent:") => Self::Agent,
            Some(_) => Self::User,
        }
    }

    /// Bounded telemetry label.
    #[must_use]
    pub fn as_label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Agent => "agent",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_buckets() {
        assert_eq!(PrincipalClass::from_str_opt(None), PrincipalClass::System);
        assert_eq!(
            PrincipalClass::from_str_opt(Some("alice")),
            PrincipalClass::User
        );
        assert_eq!(
            PrincipalClass::from_str_opt(Some("agent.scout")),
            PrincipalClass::Agent
        );
        assert_eq!(
            PrincipalClass::from_str_opt(Some("agent:scout")),
            PrincipalClass::Agent
        );
    }

    #[test]
    fn label_is_stable() {
        assert_eq!(PrincipalClass::System.as_label(), "system");
        assert_eq!(PrincipalClass::User.as_label(), "user");
        assert_eq!(PrincipalClass::Agent.as_label(), "agent");
    }
}
