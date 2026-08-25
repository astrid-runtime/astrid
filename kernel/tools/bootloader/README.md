# bootloader

[![Docs](https://docs.rs/bootloader/badge.svg)](https://docs.rs/bootloader)
[![Build Status](https://github.com/rust-osdev/bootloader/actions/workflows/build.yml/badge.svg)](https://github.com/rust-osdev/bootloader/actions/workflows/build.yml)
[![Join the chat at https://rust-osdev.zulipchat.com](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://rust-osdev.zulipchat.com)

An experimental x86_64 bootloader that works on both BIOS and UEFI systems. Written in Rust and some inline assembly, buildable on all platforms without additional build-time dependencies (just some `rustup` components).

## Requirements

You need a nightly [Rust](https://www.rust-lang.org) compiler with the `llvm-tools-preview` component, which can be installed through `rustup component add llvm-tools-preview`.

## Usage

To use this crate, you need to adjust your kernel to be bootable first. Then you can create a bootable disk image from your compiled kernel. These steps are explained in detail below.

### Migrating from older bootloader version

If you're already using an older version of the `bootloader` crate, follow our [migration guides](docs/migration).

### Starting from scratch

Our [basic example](examples/basic/basic-os.md) showcases an OS that boots a minimal kernel using `bootloader`.

### Using an existing kernel

To combine your kernel with `bootloader` and create a bootable disk image, follow these steps:

#### Make your kernel compatible with `bootloader`

- Add a dependency on the `bootloader_api` crate in your kernel's `Cargo.toml`.
- Your kernel binary should be `#![no_std]` and `#![no_main]`.
- Define an entry point function with the signature `fn kernel_main(boot_info: &'static mut bootloader_api::BootInfo) -> !`. The function name can be arbitrary.
  - The `boot_info` argument provides information about available memory, the framebuffer, and more. See the API docs for `bootloader_api` crate for details.
- Use the `entry_point` macro to register the entry point function: `bootloader_api::entry_point!(kernel_main);`
  - The macro checks the signature of your entry point function and generates a `_start` entry point symbol for it. (If you use a linker script, make sure that you don't change the entry point name to something else.)
  - To use non-standard configuration, you can pass a second argument of type `&'static bootloader_api::BootloaderConfig` to the `entry_point` macro. For example, you can require a specific stack size for your kernel:
    ```rust
    const CONFIG: bootloader_api::BootloaderConfig = {
        let mut config = bootloader_api::BootloaderConfig::new_default();
        config.kernel_stack_size = 100 * 1024; // 100 KiB
        config
    };
    bootloader_api::entry_point!(kernel_main, config = &CONFIG);
    ```
- Compile your kernel to an ELF executable by running **`cargo build --target x86_64-unknown-none`**. You might need to run `rustup target add x86_64-unknown-none` for BIOS and `rustup target add x86_64-unknown-uefi` for UEFI before to download precompiled versions of the `std`, `core` and `alloc` crates.
- Thanks to the `entry_point` macro, the compiled executable contains a special section with metadata and the serialized config, which will enable the `bootloader` crate to load it.

#### Creating a bootable image

- Move your full kernel code into a `kernel` subdirectory.
- Create a new `os` crate at the top level
    ```sh
    $ cargo init --bin
    ```
- Define a [workspace](https://doc.rust-lang.org/cargo/reference/workspaces.html).
    ```toml
    # in Cargo.toml
    [workspace]
    resolver = "3"
    members = []
    ```
- Add your kernel as a workspace member.
    ```sh
    $ cargo new kernel --bin
    ```
- Enable the workspace to build your kernel:
  - Set up an [artifact dependency](https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#artifact-dependencies) to add your `kernel` crate as a `build-dependency`:
      ```toml
      # in Cargo.toml
      [build-dependencies]
      kernel = { path = "kernel", artifact = "bin", target = "x86_64-unknown-none" }
      ```
      Enable the unstable artifact-dependencies feature:
      ```toml
      # .cargo/config.toml
      [unstable]
      bindeps = true
      ```
      Experimental features are only available on the nightly channel:
      ```toml
      # rust-toolchain.toml
      [toolchain]
      channel = "nightly"
      targets = ["x86_64-unknown-none", "x86_64-unknown-uefi"]
      ```
  - Alternatively, you can use [`std::process::Command`](https://doc.rust-lang.org/stable/std/process/struct.Command.html) to invoke the build command of your kernel in the `build.rs` script.
- Create a [`build.rs`](https://doc.rust-lang.org/cargo/reference/build-scripts.html) build script in the `os` crate. See our [disk image creation template](docs/create-disk-image.md) for a more detailed example.
  - Obtain the path to the kernel executable. When using an artifact dependency, you can retrieve this path using `std::env::var_os("CARGO_BIN_FILE_MY_KERNEL_my-kernel")`
  - Use `bootloader::UefiBoot` and/or `bootloader::BiosBoot` to create a bootable disk image with your kernel.
- Do something with the bootable disk images in your `main.rs` function. For example, run them with QEMU.

See our [disk image creation template](docs/create-disk-image.md) for a more detailed example.

## Architecture

This project is split into three separate entities:

- A [`bootloader_api`](./api) library with the entry point, configuration, and boot info definitions.
  - Kernels should include this library as a normal cargo dependency.
  - The provided `entry_point` macro will encode the configuration settings into a separate ELF section of the compiled kernel executable.
- [BIOS](./bios) and [UEFI](./uefi) binaries that contain the actual bootloader implementation.
  - The implementations share a higher-level [common library](./common).
  - Both implementations load the kernel at runtime from a FAT partition. This FAT partition is created
  - The configuration is read from a special section of the kernel's ELF file, which is created by the `entry_point` macro of the `bootloader_api` library.
- A `bootloader` library to create bootable disk images that run a given kernel. This library is the top-level crate in this project.
  - The library builds the BIOS and UEFI implementations in the [`build.rs`](./build.rs).
  - It provides functions to create FAT-formatted bootable disk images, based on the compiled BIOS and UEFI bootloaders.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
