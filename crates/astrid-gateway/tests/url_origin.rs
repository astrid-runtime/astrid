//! Pin the dependency's nonrecursive blob-origin behavior and gateway boundary.
use astrid_gateway::GatewayConfig;
use url::{Origin, Url};

#[test]
fn nested_blob_origins_are_opaque_without_recursive_origin_evaluation() {
    // This shallow assertion fails on vulnerable url 2.5.8 before reaching
    // the large case, so the negative control never aborts the test process.
    let shallow = Url::parse("blob:blob:https://example.com/id").unwrap();
    assert!(
        matches!(shallow.origin(), Origin::Opaque(_)),
        "nested blob URLs must not inherit a tuple origin"
    );
    let nested = format!("{}https://example.com/", "blob:".repeat(10_000));
    let deep = Url::parse(&nested).unwrap();
    assert!(matches!(deep.origin(), Origin::Opaque(_)));
    assert_eq!(url::quirks::origin(&deep), "null");
}

#[test]
fn ordinary_url_origins_and_gateway_cors_validation_preserve_their_contracts() {
    for (raw, expected) in [
        ("http://example.com/path", "http://example.com"),
        ("https://example.com/path", "https://example.com"),
        ("https://example.com:8443/path", "https://example.com:8443"),
        ("ws://example.com/socket", "ws://example.com"),
        ("wss://example.com/socket", "wss://example.com"),
        ("blob:https://example.com/id", "https://example.com"),
    ] {
        assert_eq!(
            Url::parse(raw).unwrap().origin().ascii_serialization(),
            expected
        );
    }
    for origin in [
        "http://localhost:8080",
        "https://example.com",
        "https://example.com:8443",
    ] {
        let config = GatewayConfig {
            cors_allow_origins: vec![origin.to_owned()],
            ..GatewayConfig::default()
        };
        config.validate().unwrap();
    }
    let nested = format!("{}https://example.com/", "blob:".repeat(10_000));
    for origin in [
        "blob:https://example.com/id",
        "blob:blob:https://example.com/id",
        "file:///tmp/untrusted",
        "ws://example.com",
        "https://example.com/",
        nested.as_str(),
    ] {
        let config = GatewayConfig {
            cors_allow_origins: vec![origin.to_owned()],
            ..GatewayConfig::default()
        };
        assert!(
            config.validate().is_err(),
            "gateway origin policy became permissive"
        );
    }
}
