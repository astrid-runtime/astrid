fn main() {
    #[cfg(all(target_os = "windows", target_env = "msvc"))]
    winfsp_wrs_build::build();
}
