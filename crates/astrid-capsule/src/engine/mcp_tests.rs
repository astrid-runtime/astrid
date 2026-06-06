#[cfg(test)]
mod tests {
    use crate::context::CapsuleContext;
    use crate::engine::ExecutionEngine;
    use crate::engine::mcp::McpHostEngine;
    use crate::manifest::{CapabilitiesDef, CapsuleManifest, McpServerDef, PackageDef};
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    use astrid_mcp::testing::test_secure_mcp_client;

    fn dummy_manifest(command: &str, allowed_commands: Vec<&str>) -> CapsuleManifest {
        CapsuleManifest {
            package: PackageDef {
                name: "test-capsule".to_string(),
                version: "1.0.0".to_string(),
                description: None,
                authors: vec![],
                repository: None,
                homepage: None,
                documentation: None,
                license: None,
                license_file: None,
                readme: None,
                keywords: vec![],
                categories: vec![],
                astrid_version: None,
                publish: None,
                include: None,
                exclude: None,
                metadata: None,
            },
            components: vec![],
            imports: HashMap::new(),
            exports: HashMap::new(),
            capabilities: CapabilitiesDef {
                net: vec![],
                net_bind: vec![],
                net_connect: vec![],
                kv: vec![],
                fs_read: vec![],
                fs_write: vec![],
                host_process: allowed_commands.into_iter().map(String::from).collect(),
                uplink: false,
                ipc_publish: vec![],
                ipc_subscribe: vec![],
                identity: vec![],
                allow_prompt_injection: false,
            },
            env: HashMap::new(),
            context_files: vec![],
            mcp_servers: vec![McpServerDef {
                id: "test-server".to_string(),
                description: None,
                server_type: Some("stdio".to_string()),
                command: Some(command.to_string()),
                args: vec![],
            }],
            skills: vec![],
            commands: vec![],
            uplinks: vec![],
            topics: vec![],
            publishes: ::std::collections::HashMap::new(),
            subscribes: ::std::collections::HashMap::new(),
            tools: ::std::vec::Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_capability_bypass_prevention() {
        let temp_dir = tempdir().unwrap();
        let capsule_dir = temp_dir.path();

        // Malicious scenario: The user granted "npx".
        // The capsule tries to execute "./bin/npx-malicious"
        // If we check the substring AFTER path resolution, it might pass because "npx" is in the path.
        // We must ensure it fails against the raw "./bin/npx-malicious" string.
        let manifest = dummy_manifest("./bin/npx-malicious", vec!["npx"]);
        let mcp_client = test_secure_mcp_client();

        let mut engine = McpHostEngine::new(
            manifest,
            McpServerDef {
                id: "test".to_string(),
                description: None,
                server_type: Some("stdio".to_string()),
                command: Some("./bin/npx-malicious".to_string()),
                args: vec![],
            },
            capsule_dir.to_path_buf(),
            mcp_client,
        );

        // Dummy context
        let bus = std::sync::Arc::new(astrid_events::EventBus::new());
        let mem_kv = std::sync::Arc::new(astrid_storage::MemoryKvStore::new());
        let kv = astrid_storage::ScopedKvStore::new(mem_kv, "test").unwrap();
        let ctx = CapsuleContext {
            principal: astrid_core::PrincipalId::default(),
            workspace_root: std::path::PathBuf::from("/"),
            home_root: None,
            event_bus: bus,
            kv,
            cli_socket_listener: None,
            capsule_registry: None,
            session_token: None,
            allowance_store: None,
            identity_store: None,
            schema_catalog: std::sync::Arc::new(crate::schema_catalog::SchemaCatalog::new()),
            profile_cache: None,
            overlay_registry: None,
            group_config: None,
        };

        let result = engine.load(&ctx).await;

        // It must explicitly fail the security check
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Security Check Failed"));
    }

    #[tokio::test]
    async fn test_fat_binary_resolution() {
        let temp_dir = tempdir().unwrap();
        let capsule_dir = temp_dir.path();

        // 1. Create a dummy fat binary wrapper directory
        let bin_dir = capsule_dir.join("bin").join("my-tool");
        fs::create_dir_all(&bin_dir).unwrap();

        // 2. Create the exact architectural slice for this machine
        let host_triple = env!("TARGET");
        let arch_slice = bin_dir.join(host_triple);
        fs::write(&arch_slice, "#!/bin/sh\necho 'hello'").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&arch_slice, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // The user granted capability for "bin/my-tool"
        let manifest = dummy_manifest("bin/my-tool", vec!["bin/my-tool"]);
        let mcp_client = test_secure_mcp_client();

        let mut engine = McpHostEngine::new(
            manifest,
            McpServerDef {
                id: "test".to_string(),
                description: None,
                server_type: Some("stdio".to_string()),
                command: Some("bin/my-tool".to_string()),
                args: vec![],
            },
            capsule_dir.to_path_buf(),
            mcp_client,
        );

        let bus = std::sync::Arc::new(astrid_events::EventBus::new());
        let mem_kv = std::sync::Arc::new(astrid_storage::MemoryKvStore::new());
        let kv = astrid_storage::ScopedKvStore::new(mem_kv, "test").unwrap();
        let ctx = CapsuleContext {
            principal: astrid_core::PrincipalId::default(),
            workspace_root: std::path::PathBuf::from("/"),
            home_root: None,
            event_bus: bus,
            kv,
            cli_socket_listener: None,
            capsule_registry: None,
            session_token: None,
            allowance_store: None,
            identity_store: None,
            schema_catalog: std::sync::Arc::new(crate::schema_catalog::SchemaCatalog::new()),
            profile_cache: None,
            overlay_registry: None,
            group_config: None,
        };

        let result = engine.load(&ctx).await;

        // It should attempt the connection and fail at the handshake step (meaning it successfully found and spawned the fat binary slice)
        assert!(result.is_err(), "Test failed: {:?}", result.err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("MCP handshake failed")
                || err_msg.contains("Failed to start MCP server"),
            "Expected handshake or start failure, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_fat_binary_missing_architecture() {
        let temp_dir = tempdir().unwrap();
        let capsule_dir = temp_dir.path();

        // 1. Create a dummy fat binary wrapper directory
        let bin_dir = capsule_dir.join("bin").join("my-tool");
        fs::create_dir_all(&bin_dir).unwrap();

        // 2. Create an INCORRECT architectural slice (e.g. they only shipped Windows)
        let arch_slice = bin_dir.join("x86_64-pc-windows-msvc");
        fs::write(&arch_slice, "MZ...").unwrap();

        let manifest = dummy_manifest("bin/my-tool", vec!["bin/my-tool"]);
        let mcp_client = test_secure_mcp_client();

        let mut engine = McpHostEngine::new(
            manifest,
            McpServerDef {
                id: "test".to_string(),
                description: None,
                server_type: Some("stdio".to_string()),
                command: Some("bin/my-tool".to_string()),
                args: vec![],
            },
            capsule_dir.to_path_buf(),
            mcp_client,
        );

        let bus = std::sync::Arc::new(astrid_events::EventBus::new());
        let mem_kv = std::sync::Arc::new(astrid_storage::MemoryKvStore::new());
        let kv = astrid_storage::ScopedKvStore::new(mem_kv, "test").unwrap();
        let ctx = CapsuleContext {
            principal: astrid_core::PrincipalId::default(),
            workspace_root: std::path::PathBuf::from("/"),
            home_root: None,
            event_bus: bus,
            kv,
            cli_socket_listener: None,
            capsule_registry: None,
            session_token: None,
            allowance_store: None,
            identity_store: None,
            schema_catalog: std::sync::Arc::new(crate::schema_catalog::SchemaCatalog::new()),
            profile_cache: None,
            overlay_registry: None,
            group_config: None,
        };

        let result = engine.load(&ctx).await;

        // It must fail because our env!("TARGET") slice wasn't found inside the directory
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        println!("Error Message Output: {}", err_msg);
        assert!(err_msg.contains("does not contain a valid slice for the current architecture"));
    }
}
