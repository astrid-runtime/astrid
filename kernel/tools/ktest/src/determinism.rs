//! Image determinism is a reported measurement, never coerced to green.

use std::path::Path;

use anyhow::{Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Determinism {
    Pass,
    Fail,
}

impl Determinism {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

pub fn compare_images(a: &Path, b: &Path) -> Result<Determinism> {
    let bytes_a = std::fs::read(a).with_context(|| format!("reading {}", a.display()))?;
    let bytes_b = std::fs::read(b).with_context(|| format!("reading {}", b.display()))?;
    let hash_a = blake3::hash(&bytes_a);
    let hash_b = blake3::hash(&bytes_b);
    if hash_a == hash_b {
        println!("determinism: identical images (blake3 {})", hash_a.to_hex());
        return Ok(Determinism::Pass);
    }
    println!(
        "determinism: DIVERGENT (blake3 {} vs {})",
        hash_a.to_hex(),
        hash_b.to_hex()
    );
    report_ranges(&bytes_a, &bytes_b);
    Ok(Determinism::Fail)
}

fn report_ranges(a: &[u8], b: &[u8]) {
    if a.len() != b.len() {
        println!("  image sizes differ: {} vs {} bytes", a.len(), b.len());
    }
    let n = a.len().min(b.len());
    let mut ranges = 0usize;
    let mut i = 0usize;
    while i < n {
        if a[i] != b[i] {
            let start = i;
            while i < n && a[i] != b[i] {
                i += 1;
            }
            if ranges < 16 {
                println!("  differ: bytes [{start:#x}..{i:#x}) ({} bytes)", i - start);
            }
            ranges += 1;
        } else {
            i += 1;
        }
    }
    println!("  total differing ranges: {ranges}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn identical_bytes_are_pass() {
        let dir = std::env::temp_dir().join("astrid-ktest-det-pass");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a");
        let b = dir.join("b");
        fs::write(&a, b"same").unwrap();
        fs::write(&b, b"same").unwrap();
        assert_eq!(compare_images(&a, &b).unwrap(), Determinism::Pass);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn divergent_bytes_are_fail_not_coerced() {
        let dir = std::env::temp_dir().join("astrid-ktest-det-fail");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a");
        let b = dir.join("b");
        fs::write(&a, b"left").unwrap();
        fs::write(&b, b"right").unwrap();
        assert_eq!(compare_images(&a, &b).unwrap(), Determinism::Fail);
        let _ = fs::remove_dir_all(&dir);
    }
}
