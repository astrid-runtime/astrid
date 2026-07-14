use super::*;

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, GroupConfig};
use astrid_core::profile::{AuthConfig, AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};
use astrid_events::ipc::{IpcPayload, Topic};

use crate::access::CapsuleAccessResolver;
use crate::capsule::{Capsule, CapsuleId, CapsuleState, InterceptResult};
use crate::context::CapsuleContext;
use crate::error::CapsuleResult;
use crate::manifest::{CapabilitiesDef, CapsuleManifest, PackageDef, SubscribeDef};
use crate::profile_cache::PrincipalProfileCache;

struct TestCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
    invoked: Arc<AtomicBool>,
}

impl TestCapsule {
    fn new(name: &str, topics: &[&str]) -> (Self, Arc<AtomicBool>) {
        let invoked = Arc::new(AtomicBool::new(false));
        let subscribes = topics
            .iter()
            .map(|topic| {
                (
                    (*topic).to_string(),
                    SubscribeDef {
                        wit: "opaque".into(),
                        version: None,
                        tag: None,
                        rev: None,
                        branch: None,
                        path: None,
                        handler: Some("test_action".into()),
                        priority: Some(100),
                    },
                )
            })
            .collect();
        (
            Self {
                id: CapsuleId::from_static(name),
                manifest: CapsuleManifest {
                    package: PackageDef {
                        name: name.into(),
                        version: "0.0.1".into(),
                        description: None,
                        authors: Vec::new(),
                        repository: None,
                        homepage: None,
                        documentation: None,
                        license: None,
                        license_file: None,
                        readme: None,
                        keywords: Vec::new(),
                        categories: Vec::new(),
                        astrid_version: None,
                        publish: None,
                        include: None,
                        exclude: None,
                        metadata: None,
                    },
                    components: Vec::new(),
                    imports: HashMap::new(),
                    exports: HashMap::new(),
                    capabilities: CapabilitiesDef::default(),
                    env: HashMap::new(),
                    context_files: Vec::new(),
                    commands: Vec::new(),
                    mcp_servers: Vec::new(),
                    skills: Vec::new(),
                    uplinks: Vec::new(),
                    publishes: HashMap::new(),
                    subscribes,
                    tools: Vec::new(),
                },
                invoked: Arc::clone(&invoked),
            },
            invoked,
        )
    }
}

#[async_trait]
impl Capsule for TestCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }

    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }

    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }

    async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }

    async fn unload(&mut self) -> CapsuleResult<()> {
        Ok(())
    }

    async fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        self.invoked.store(true, Ordering::SeqCst);
        Ok(InterceptResult::Continue(Vec::new()))
    }
}

struct ResolverFixture {
    _dir: tempfile::TempDir,
    home: AstridHome,
    cache: Arc<PrincipalProfileCache>,
    resolver: CapsuleAccessResolver,
}

fn resolver_fixture() -> ResolverFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
    let groups = Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));
    let resolver = CapsuleAccessResolver::new(Arc::clone(&cache), groups);
    ResolverFixture {
        _dir: dir,
        home,
        cache,
        resolver,
    }
}

fn write_profile(home: &AstridHome, principal: &str, profile: &PrincipalProfile) {
    let principal = astrid_core::PrincipalId::new(principal).unwrap();
    profile.save(home, &principal).expect("save profile");
}

fn device(seed: char, scope: DeviceScope) -> DeviceKey {
    DeviceKey::new(seed.to_string().repeat(64), scope, None, 0)
}

fn registry_for(capsule: TestCapsule, principals: &[&str]) -> Arc<RwLock<CapsuleRegistry>> {
    let mut registry = CapsuleRegistry::new();
    let hash = crate::registry::WasmHash::synthetic(
        capsule.id().as_str(),
        &capsule.manifest().package.version,
    );
    let capsule_id = capsule.id().clone();
    let first = astrid_core::PrincipalId::new(principals[0]).unwrap();
    registry
        .register_for(Box::new(capsule), hash.clone(), &first)
        .unwrap();
    for principal in &principals[1..] {
        registry
            .register_existing(
                &capsule_id,
                &hash,
                &astrid_core::PrincipalId::new(*principal).unwrap(),
            )
            .unwrap();
    }
    Arc::new(RwLock::new(registry))
}

async fn matching(
    registry: &RwLock<CapsuleRegistry>,
    topic: &str,
    principal: &str,
    device_key_id: Option<&str>,
    resolver: Option<&CapsuleAccessResolver>,
    bus: &EventBus,
) -> usize {
    find_matching_interceptors(
        registry,
        topic,
        Some(principal),
        device_key_id,
        resolver,
        bus,
    )
    .await
    .len()
}

async fn assert_no_grant_required(receiver: &mut astrid_events::EventReceiver) {
    assert!(
        tokio::time::timeout(Duration::from_millis(25), receiver.recv())
            .await
            .is_err()
    );
}

async fn recv_grant_required(receiver: &mut astrid_events::EventReceiver) -> (String, String) {
    let event = tokio::time::timeout(Duration::from_millis(100), receiver.recv())
        .await
        .expect("GrantRequired timeout")
        .expect("event bus closed");
    match &*event {
        AstridEvent::Ipc { message, .. }
            if matches!(&message.payload, IpcPayload::GrantRequired { .. }) =>
        {
            let IpcPayload::GrantRequired {
                principal,
                capsule_id,
                ..
            } = &message.payload
            else {
                unreachable!()
            };
            (principal.clone(), capsule_id.clone())
        },
        other => panic!("expected GrantRequired, got {other:?}"),
    }
}

#[tokio::test]
async fn inventory_visibility_and_execution_authority_are_separate() {
    let fixture = resolver_fixture();
    let full = device('a', DeviceScope::Full);
    let list_only = device(
        'b',
        DeviceScope::Scoped {
            allow: vec!["capsule:list".into()],
            deny: Vec::new(),
        },
    );
    let access_any = device(
        'c',
        DeviceScope::Scoped {
            allow: vec!["capsule:access:any".into()],
            deny: Vec::new(),
        },
    );
    let access_denied = device(
        'd',
        DeviceScope::Scoped {
            allow: vec!["*".into()],
            deny: vec!["capsule:access:any".into()],
        },
    );
    let ids = [
        full.key_id.clone(),
        list_only.key_id.clone(),
        access_any.key_id.clone(),
        access_denied.key_id.clone(),
    ];
    write_profile(
        &fixture.home,
        "root",
        &PrincipalProfile {
            groups: vec![BUILTIN_ADMIN.into()],
            auth: AuthConfig {
                methods: vec![AuthMethod::Keypair],
                public_keys: vec![full, list_only, access_any, access_denied],
            },
            ..PrincipalProfile::default()
        },
    );
    let (capsule, _) = TestCapsule::new(
        "secret-tool",
        &["tool.v1.request.describe", "tool.v1.execute.do_thing"],
    );
    let registry = registry_for(capsule, &["default", "root"]);
    let (global_capsule, _) = TestCapsule::new(
        "global-tool",
        &["tool.v1.request.describe", "tool.v1.execute.do_thing"],
    );
    let global_registry = registry_for(global_capsule, &["default"]);
    let bus = EventBus::with_capacity(64);
    let mut approval = bus.subscribe_topic("astrid.v1.approval");

    assert_eq!(
        matching(
            &global_registry,
            "tool.v1.execute.do_thing",
            "root",
            None,
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        1
    );
    assert_eq!(
        matching(
            &global_registry,
            "tool.v1.execute.do_thing",
            "root",
            Some(&ids[0]),
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        1
    );
    assert_eq!(
        matching(
            &global_registry,
            "tool.v1.request.describe",
            "root",
            Some(&ids[1]),
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        1
    );
    assert_eq!(
        matching(
            &global_registry,
            "tool.v1.execute.do_thing",
            "root",
            Some(&ids[1]),
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        0
    );
    assert_no_grant_required(&mut approval).await;
    assert_eq!(
        matching(
            &registry,
            "tool.v1.execute.do_thing",
            "root",
            Some(&ids[1]),
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        0
    );
    assert_eq!(
        recv_grant_required(&mut approval).await,
        ("root".into(), "secret-tool".into())
    );
    assert_eq!(
        matching(
            &global_registry,
            "tool.v1.execute.do_thing",
            "root",
            Some(&ids[2]),
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        1
    );
    assert_eq!(
        matching(
            &registry,
            "tool.v1.execute.do_thing",
            "root",
            Some(&ids[3]),
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        0
    );
    assert_eq!(
        recv_grant_required(&mut approval).await,
        ("root".into(), "secret-tool".into())
    );
}

#[tokio::test]
async fn direct_capsule_access_any_holder_can_execute() {
    let fixture = resolver_fixture();
    let device = device(
        'f',
        DeviceScope::Scoped {
            allow: vec!["capsule:access:any".into()],
            deny: Vec::new(),
        },
    );
    let device_key_id = device.key_id.clone();
    write_profile(
        &fixture.home,
        "operator",
        &PrincipalProfile {
            grants: vec!["capsule:access:any".into()],
            auth: AuthConfig {
                methods: vec![AuthMethod::Keypair],
                public_keys: vec![device],
            },
            ..PrincipalProfile::default()
        },
    );
    let (capsule, _) = TestCapsule::new("secret-tool", &["tool.v1.execute.do_thing"]);
    let registry = registry_for(capsule, &["default"]);
    let bus = EventBus::with_capacity(64);
    assert_eq!(
        matching(
            &registry,
            "tool.v1.execute.do_thing",
            "operator",
            Some(&device_key_id),
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        1
    );
}

#[tokio::test]
async fn disabled_caller_dispatches_nothing_and_emits_no_grant() {
    let fixture = resolver_fixture();
    write_profile(
        &fixture.home,
        "disabled",
        &PrincipalProfile {
            enabled: false,
            groups: vec![BUILTIN_ADMIN.into()],
            capsules: vec!["disabled-tool".into()],
            ..PrincipalProfile::default()
        },
    );
    let (capsule, _) = TestCapsule::new(
        "disabled-tool",
        &["tool.v1.execute.do_thing", "session.v1.append"],
    );
    let registry = registry_for(capsule, &["disabled"]);
    let bus = EventBus::with_capacity(64);
    let mut approval = bus.subscribe_topic("astrid.v1.approval");

    for topic in ["tool.v1.execute.do_thing", "session.v1.append"] {
        assert_eq!(
            matching(
                &registry,
                topic,
                "disabled",
                None,
                Some(&fixture.resolver),
                &bus,
            )
            .await,
            0
        );
    }
    assert_no_grant_required(&mut approval).await;
}

#[tokio::test]
async fn invalid_or_revoked_device_never_falls_back_or_emits_grant() {
    let fixture = resolver_fixture();
    let full = device('e', DeviceScope::Full);
    let full_id = full.key_id.clone();
    let mut profile = PrincipalProfile {
        groups: vec![BUILTIN_ADMIN.into()],
        capsules: vec!["secret-tool".into()],
        auth: AuthConfig {
            methods: vec![AuthMethod::Keypair],
            public_keys: vec![full],
        },
        ..PrincipalProfile::default()
    };
    write_profile(&fixture.home, "root", &profile);
    let (capsule, _) = TestCapsule::new(
        "secret-tool",
        &["tool.v1.execute.do_thing", "session.v1.append"],
    );
    let registry = registry_for(capsule, &["root"]);
    let bus = EventBus::with_capacity(64);
    let mut approval = bus.subscribe_topic("astrid.v1.approval");
    assert_eq!(
        matching(
            &registry,
            "tool.v1.execute.do_thing",
            "root",
            Some(&full_id),
            Some(&fixture.resolver),
            &bus,
        )
        .await,
        1
    );

    profile.auth.public_keys.clear();
    write_profile(&fixture.home, "root", &profile);
    fixture
        .cache
        .invalidate(&astrid_core::PrincipalId::new("root").unwrap());

    for device_key_id in ["not-a-key-id", "0000000000000000", full_id.as_str()] {
        for topic in ["tool.v1.execute.do_thing", "session.v1.append"] {
            assert_eq!(
                matching(
                    &registry,
                    topic,
                    "root",
                    Some(device_key_id),
                    Some(&fixture.resolver),
                    &bus,
                )
                .await,
                0
            );
        }
    }
    assert_no_grant_required(&mut approval).await;
}

#[tokio::test]
async fn no_resolver_ignores_device_metadata() {
    let (capsule, invoked) = TestCapsule::new("legacy", &["tool.v1.execute.do_thing"]);
    let registry = registry_for(capsule, &["default"]);
    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());
    let message = astrid_events::ipc::IpcMessage::new(
        Topic::from_raw("tool.v1.execute.do_thing"),
        IpcPayload::Custom {
            data: serde_json::json!({}),
        },
        uuid::Uuid::nil(),
    )
    .with_principal("root")
    .with_device_key_id("not-a-key-id");
    bus.publish(AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message,
    });
    tokio::time::timeout(Duration::from_millis(500), async {
        while !invoked.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("legacy dispatch");
    handle.abort();
}
