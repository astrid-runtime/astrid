use super::*;
use std::sync::Arc;

#[tokio::test]
async fn retiring_inventory_recovers_every_interrupted_host_shape() {
    for shape in [
        "whole",
        "partial-resurrected",
        "top-level-absent",
        "volume-only",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(temp.path());
        let quota = || -> Arc<dyn crate::KvQuotaResolver<StateOwner>> {
            Arc::new(|_: &StateOwner| Ok(None))
        };
        let running = crate::open_runtime_principal_store(&home, quota())
            .await
            .unwrap();
        let first = home.root().join("etc/retire-a.conf");
        let second = home.root().join("var/retire-b.conf");
        std::fs::create_dir_all(first.parent().unwrap()).unwrap();
        std::fs::create_dir_all(second.parent().unwrap()).unwrap();
        std::fs::write(&first, b"published-a").unwrap();
        std::fs::write(&second, b"published-b").unwrap();
        publish_running_projection(&home, &running).unwrap();
        transition_retiring_projection(&home, &running).unwrap();
        assert_eq!(
            active::read(&home, &running).unwrap().unwrap().phase(),
            ReceiptPhase::Retiring
        );
        drop(running);
        match shape {
            "whole" => {},
            "partial-resurrected" => {
                std::fs::remove_file(&first).unwrap();
                std::fs::write(&first, b"resurrected stale host bytes").unwrap();
                std::fs::remove_file(&second).unwrap();
            },
            "top-level-absent" => std::fs::remove_dir_all(home.root().join("etc")).unwrap(),
            "volume-only" => astrid_core::dirs::retire_projection_root(home.root()).unwrap(),
            _ => unreachable!(),
        }
        let reopened = crate::open_runtime_principal_store(&home, quota())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&first).unwrap(), b"published-a", "{shape}");
        assert_eq!(std::fs::read(&second).unwrap(), b"published-b", "{shape}");
        let receipt = active::read(&home, &reopened).unwrap().unwrap();
        assert_eq!(receipt.phase(), ReceiptPhase::Active, "{shape}");
        assert!(
            receipt.contains_inventory_name("etc/retire-a.conf"),
            "{shape}"
        );
        assert!(
            receipt.contains_inventory_name("var/retire-b.conf"),
            "{shape}"
        );
        reopened.pack_and_retire_runtime_projection(&home).unwrap();
        assert_eq!(
            std::fs::read_dir(home.root()).unwrap().count(),
            1,
            "{shape}"
        );
    }
}
