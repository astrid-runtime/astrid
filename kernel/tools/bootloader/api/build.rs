use std::{env, fs, path::Path};

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("concat.rs");

    let combinations = [
        (1, 8),
        (1, 9),
        (2, 1),
        (2, 2),
        (4, 3),
        (16, 7),
        (23, 8),
        (31, 9),
        (40, 9),
        (49, 9),
        (58, 9),
        (67, 10),
        (77, 10),
        (87, 1),
        (88, 9),
        (97, 9),
        (106, 9),
        (115, 9),
        (124, 9),
    ];

    let mut code = String::new();
    for (i, j) in combinations {
        code += &format!(
            "pub const fn concat_{i}_{j}(a: [u8; {i}], b: [u8; {j}]) -> [u8; {i} + {j}] {{
                    [{a}, {b}]
                }}",
            i = i,
            j = j,
            a = (0..i)
                .map(|idx| format!("a[{idx}]"))
                .collect::<Vec<_>>()
                .join(","),
            b = (0..j)
                .map(|idx| format!("b[{idx}]"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    fs::write(dest_path, code).unwrap();
    println!("cargo:rerun-if-changed=build.rs");

    let version_major: u16 = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap();
    let version_minor: u16 = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap();
    let version_patch: u16 = env!("CARGO_PKG_VERSION_PATCH").parse().unwrap();
    let pre_release: bool = !env!("CARGO_PKG_VERSION_PRE").is_empty();

    fs::write(
        Path::new(&out_dir).join("version_info.rs"),
        format!(
            "
            pub const VERSION_MAJOR: u16 = {version_major};
            pub const VERSION_MINOR: u16 = {version_minor};
            pub const VERSION_PATCH: u16 = {version_patch};
            pub const VERSION_PRE: bool = {pre_release};
            "
        ),
    )
    .unwrap();
    println!("cargo:rerun-if-changed=Cargo.toml");
}
