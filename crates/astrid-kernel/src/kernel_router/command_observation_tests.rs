//! Caller policy is exposed through existing command-list authority, not quota administration.
use super::*;
use astrid_capsule::capsule::{Capsule, CapsuleId, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::CapsuleResult;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::profile::PrincipalProfile;

struct CommandCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
}

impl CommandCapsule {
    fn new() -> Self {
        Self {
            id: CapsuleId::new("slow-command").unwrap(),
            manifest: toml::from_str(
                r#"
[package]
name = "slow-command"
version = "0.0.1"
[[command]]
name = "slow"
kind = "cli"
"#,
            )
            .unwrap(),
        }
    }
}

#[async_trait::async_trait]
impl Capsule for CommandCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }
    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }
    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }
    async fn load(&mut self, _: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }
    async fn unload(&mut self) -> CapsuleResult<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn command_wait_metadata_uses_each_authorized_callers_policy() {
    let temp = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(temp.path())).await;
    for (name, seconds) in [("alice", 600), ("bob", 12)] {
        let caller = PrincipalId::new(name).unwrap();
        let profile = PrincipalProfile {
            // No quota management or global inventory grant.
            grants: vec!["self:capsule:list".into()],
            capsules: vec!["slow-command".into()],
            quotas: astrid_core::Quotas {
                max_timeout_secs: seconds,
                ..Default::default()
            },
            ..Default::default()
        };
        profile
            .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, &caller))
            .unwrap();
        kernel.profile_cache.invalidate(&caller);
        kernel
            .capsules
            .write()
            .await
            .register_for(
                Box::new(CommandCapsule::new()),
                astrid_capsule::registry::WasmHash::synthetic("slow-command", "0.0.1"),
                &caller,
            )
            .unwrap();
        let request_topic = Topic::kernel_request(format!("get_commands.{name}"));
        let response_topic = response_topic_for(request_topic.as_str());
        let mut response = kernel.event_bus.subscribe_topic(response_topic.as_str());
        let mut limiter = ManagementRateLimiter::from_kernel(&kernel);
        handle_request(
            &kernel,
            &mut limiter,
            request_topic,
            caller,
            None,
            KernelRequest::GetCommands,
        )
        .await;
        let commands = astrid_runtime::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let event = response.recv().await.unwrap();
                if let astrid_events::AstridEvent::Ipc { message, .. } = &*event
                    && let IpcPayload::RawJson(value) = &message.payload
                {
                    let KernelResponse::Commands(commands) =
                        serde_json::from_value(value.clone()).unwrap()
                    else {
                        panic!("authorized command listing must return commands");
                    };
                    return commands;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].provider_capsule, "slow-command");
        assert_eq!(commands[0].caller_max_timeout_secs, Some(seconds));
    }
}
