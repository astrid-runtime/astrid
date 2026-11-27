//! Check both lifecycle guards inside the synchronous daemon subscriber.
use super::*;

struct OnGuestError<F>(F);

impl<F: Fn() + Send + Sync + 'static> tracing::Subscriber for OnGuestError<F> {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::ERROR && metadata.fields().field("plugin").is_some()
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {
        (self.0)();
    }
}

#[tokio::test]
async fn owner_and_caller_remain_admitted_until_the_mirrored_record_returns() {
    let (_parent, root, mut state, tracker) = fixture();
    let pending = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let owner = state.principal.clone();
    let peer = PrincipalId::new("log-peer").unwrap();
    assert_ne!(owner, peer);
    caller(&mut state, &peer);

    let subscriber = OnGuestError({
        let tracker = Arc::clone(&tracker);
        let owner = owner.clone();
        let peer = peer.clone();
        let path = root.home.root().join(&pending.deferred().target);
        move || {
            assert!(
                std::fs::read_to_string(&path)
                    .unwrap()
                    .contains("mirrored record")
            );
            assert_eq!(tracker.active(&owner), 1);
            assert_eq!(tracker.active(&peer), 1);
            tracker.retire(&owner);
            assert!(tracker.begin(&owner).is_none());
        }
    });
    tracing::subscriber::with_default(subscriber, || {
        state.log(LogLevel::Error, "mirrored record".into());
    });

    assert!(
        tracker.begin(&owner).is_none(),
        "subscriber must have retired the owner"
    );
    assert_eq!(tracker.active(&owner), 0);
    assert_eq!(tracker.active(&peer), 0);
    state.log(LogLevel::Info, "refused after retirement".into());
    assert_eq!(contents(&root, &pending).lines().count(), 1);
}
