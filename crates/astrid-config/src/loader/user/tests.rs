use super::*;

fn canonical_config(root: &Path, prompt: &str) -> PathBuf {
    let path = root.join("etc/config.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, format!("[runtime]\nsystem_prompt = '{prompt}'\n")).unwrap();
    path
}

#[test]
fn canonical_only_override_does_not_fall_through_to_default_home() {
    let root = tempfile::tempdir().unwrap();
    let user_home = root.path().join("user");
    let selected = root.path().join("selected");
    canonical_config(&user_home.join(".astrid"), "fallback");
    canonical_config(&selected, "selected");

    let overlays = discover_user_config(&user_home, selected.to_str()).unwrap();
    assert_eq!(overlays.len(), 1);
    assert_eq!(
        overlays[0].1,
        selected.canonicalize().unwrap().join("etc/config.toml")
    );
    assert_eq!(
        overlays[0].0["runtime"]["system_prompt"].as_str(),
        Some("selected")
    );
}

#[test]
fn default_home_discovers_canonical_only_overlay() {
    let user_home = tempfile::tempdir().unwrap();
    let path = canonical_config(&user_home.path().join(".astrid"), "default canonical");

    let overlays = discover_user_config(user_home.path(), None).unwrap();
    assert_eq!(overlays.len(), 1);
    assert_eq!(overlays[0].1, path);
    assert_eq!(
        overlays[0].0["runtime"]["system_prompt"].as_str(),
        Some("default canonical")
    );
}
