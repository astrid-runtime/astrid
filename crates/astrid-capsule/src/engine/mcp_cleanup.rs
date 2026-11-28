//! Registration and cleanup transitions serialized by the teardown mutex.
//!
//! Beginning cleanup freezes the name registered at that moment into the only
//! worker token. Later registration and duplicate starts leave the phase
//! unchanged. Completion accepts only the token that still carries that name.

pub(super) enum Phase {
    Open(Option<String>),
    Draining(Option<String>),
    Done,
}

/// Owned by the single worker elected by [`Phase::begin`].
pub(super) struct Cleanup {
    target: Option<String>,
}

impl Cleanup {
    pub(super) fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }
}

impl Phase {
    pub(super) fn register(&mut self, target: String) -> bool {
        match self {
            Self::Open(slot) => {
                *slot = Some(target);
                true
            },
            Self::Draining(_) | Self::Done => false,
        }
    }

    pub(super) fn target(&self) -> Option<String> {
        match self {
            Self::Open(Some(name)) | Self::Draining(Some(name)) => Some(name.clone()),
            Self::Open(None) | Self::Draining(None) | Self::Done => None,
        }
    }

    pub(super) fn begin(&mut self) -> Option<Cleanup> {
        if let Self::Open(slot) = self {
            let retained = slot.clone();
            let target = slot.take();
            *self = Self::Draining(retained);
            Some(Cleanup { target })
        } else {
            None
        }
    }

    pub(super) fn finish(&mut self, work: Cleanup) -> bool {
        let same_target = match (&*self, work.target()) {
            (Self::Draining(Some(owned)), Some(done)) => owned.as_str() == done,
            (Self::Draining(None), None) => true,
            (Self::Open(_) | Self::Draining(_) | Self::Done, _) => false,
        };
        if same_target {
            *self = Self::Done;
        }
        same_target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_freezes_the_registered_name() {
        let mut phase = Phase::Open(None);
        assert!(phase.register("capsule:test".to_string()));
        assert!(phase.register("capsule:replaced".to_string()));

        let worker = phase.begin().expect("open phase elects one worker");
        assert_eq!(worker.target(), Some("capsule:replaced"));
        assert!(!phase.register("other-server".to_string()));
        assert!(phase.begin().is_none());
        assert_eq!(phase.target().as_deref(), Some("capsule:replaced"));

        assert!(phase.finish(worker));
        assert!(phase.target().is_none());
        assert!(!phase.register("late-server".to_string()));
        assert!(phase.begin().is_none());
    }

    #[test]
    fn empty_retirement_rejects_later_registration() {
        let mut phase = Phase::Open(None);
        let worker = phase
            .begin()
            .expect("empty registration still elects a worker");
        assert!(worker.target().is_none());
        assert!(!phase.register("late-server".to_string()));
        assert!(phase.finish(worker));
        assert!(matches!(phase, Phase::Done));
    }

    #[test]
    fn foreign_token_cannot_complete_cleanup() {
        let mut current = Phase::Open(None);
        let mut foreign = Phase::Open(None);
        assert!(current.register("capsule:one".to_string()));
        assert!(foreign.register("capsule:two".to_string()));

        let own = current.begin().expect("current worker");
        let other = foreign.begin().expect("foreign worker");
        assert!(!current.finish(other));
        assert_eq!(current.target().as_deref(), Some("capsule:one"));
        assert!(current.finish(own));
        assert!(current.target().is_none());
    }
}
