use std::env;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BenchmarkEnvironment {
    pub operating_system: &'static str,
    pub architecture: &'static str,
    pub host_triple: &'static str,
    pub target_triple: &'static str,
    pub cpu: String,
    pub rustc: &'static str,
    pub build_profile: &'static str,
}

pub fn current() -> BenchmarkEnvironment {
    BenchmarkEnvironment {
        operating_system: env::consts::OS,
        architecture: env::consts::ARCH,
        host_triple: env!("ASTRID_EVIDENCE_HOST"),
        target_triple: env!("ASTRID_EVIDENCE_TARGET"),
        cpu: detected_cpu().unwrap_or_else(|| "unavailable".to_owned()),
        rustc: env!("ASTRID_EVIDENCE_RUSTC"),
        build_profile: env!("ASTRID_EVIDENCE_PROFILE"),
    }
}

fn detected_cpu() -> Option<String> {
    env::var("ASTRID_EVIDENCE_CPU")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(platform_cpu)
}

#[cfg(target_os = "macos")]
fn platform_cpu() -> Option<String> {
    let output = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()?;
    command_value(output)
}

#[cfg(target_os = "linux")]
fn platform_cpu() -> Option<String> {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()?
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            matches!(name.trim(), "model name" | "Hardware")
                .then(|| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
}

#[cfg(target_os = "windows")]
fn platform_cpu() -> Option<String> {
    env::var("PROCESSOR_IDENTIFIER")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_cpu() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn command_value(output: std::process::Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_environment_is_explicit() {
        let environment = current();
        assert!(!environment.operating_system.is_empty());
        assert!(!environment.architecture.is_empty());
        assert!(!environment.host_triple.is_empty());
        assert!(!environment.target_triple.is_empty());
        assert!(!environment.rustc.is_empty());
        assert!(!environment.build_profile.is_empty());
    }
}
