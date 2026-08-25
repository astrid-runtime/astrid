# Template: Create a Disk Image

The [`bootloader`](https://docs.rs/bootloader/0.11) crate provides simple functions to create bootable disk images from a kernel. The basic idea is to build your kernel first and then invoke a builder function that calls the disk image creation functions of the `bootloader` crate.

A good way to implement this is to move your kernel into a `kernel` subdirectory. Then you can create
a new `os` crate at the top level that defines a [workspace](https://doc.rust-lang.org/cargo/reference/workspaces.html). The root package has build-dependencies on the `kernel` [artifact](https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#artifact-dependencies) and on the bootloader crate. This allows you to create the bootable disk image in a [cargo build script](https://doc.rust-lang.org/cargo/reference/build-scripts.html) and launch the created image in QEMU in the `main` function.

Our [basic example](/examples/basic/basic-os.md) showcases this setup:
- [Cargo.toml](/examples/basic/Cargo.toml)
    - create a workspace & add kernel as member
    - add kernel as build-dependency
    - add ovmf-prebuilt for UEFI booting in QEMU
- [.cargo/config.toml](/examples/basic/.cargo/config.toml)
    - enable the unstable artifact-dependencies feature
- [rust-toolchain.toml](/examples/basic/rust-toolchain.toml)
    - change the default toolchain to nightly to use experimental features
- [build.rs](/examples/basic/build.rs)
    - create bios and uefi disk image
- [src/main.rs](/examples/basic/src/main.rs)
    - launch the image using QEMU

Now you should be able to use `cargo build` to create a bootable disk image and `cargo run bios` and `cargo run uefi` to run it in QEMU. Your kernel is automatically recompiled when it changes. For more advanced usage, you can add command-line arguments to your `main.rs` to e.g. pass additional arguments to QEMU or to copy the disk images to some path to make it easier to find them (e.g. for copying them to an thumb drive).
