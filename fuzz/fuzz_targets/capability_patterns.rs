#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use astrid_capabilities::ResourcePattern;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    pattern: String,
    resource: String,
    server: String,
    tool: String,
    path: String,
}

fuzz_target!(|data: &[u8]| {
    let mut data = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut data) else {
        return;
    };

    let pattern_has_traversal = contains_path_traversal(&input.pattern);
    let resource_has_traversal = contains_path_traversal(&input.resource);

    let compiled = ResourcePattern::new(input.pattern.clone());
    if pattern_has_traversal {
        assert!(compiled.is_err());
    }

    if let Ok(pattern) = compiled {
        if resource_has_traversal {
            assert!(!pattern.matches(&input.resource));
        }

        if !pattern.is_glob() && !resource_has_traversal {
            assert_eq!(
                pattern.matches(pattern.as_str()),
                !contains_path_traversal(pattern.as_str())
            );
        }
    }

    let exact = ResourcePattern::exact(input.pattern.clone());
    if pattern_has_traversal {
        assert!(exact.is_err());
    } else if let Ok(exact) = exact {
        assert!(exact.matches(exact.as_str()));
        if resource_has_traversal {
            assert!(!exact.matches(&input.resource));
        }
    }

    if contains_path_traversal(&input.path) {
        assert!(ResourcePattern::file_dir(input.path.clone()).is_err());
        assert!(ResourcePattern::file_exact(input.path.clone()).is_err());
    }

    let mcp_resource = format!("mcp://{}:{}", input.server, input.tool);
    let mcp = ResourcePattern::mcp_tool(input.server.clone(), input.tool.clone());
    if contains_path_traversal(&mcp_resource) {
        assert!(mcp.is_err());
    } else if let Ok(mcp) = mcp {
        assert!(mcp.matches(&mcp_resource));
    }
});

fn contains_path_traversal(s: &str) -> bool {
    let path = s.split_once("://").map_or(s, |(_, rest)| rest);
    path.split('/').any(|segment| segment == "..")
}
