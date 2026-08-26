# Unreleased

# 0.11.16 - 2026-07-18

This release is compatible with Rust nightlies starting with `nightly-2026-07-06`.

* change `rustc-abi` in custom targets from `x86-softfloat` to `softfloat`, following [rust-lang/rust#157151](https://github.com/rust-lang/rust/pull/157151) ([#569](https://github.com/rust-osdev/bootloader/pull/569))
* [Fix nightly breakage (nightly-2026-05-10)](https://github.com/rust-osdev/bootloader/pull/563)
* [Add missing `x86_64-unknown-uefi` target](https://github.com/rust-osdev/bootloader/pull/557)
* [Bump `uart_16550` to 0.6.0](https://github.com/rust-osdev/bootloader/pull/565)
* [Bump `critical-section`, `atomic-polyfill`, and `heapless`](https://github.com/rust-osdev/bootloader/pull/567)
* [Speed up BIOS disk reads by merging contiguous cluster reads and skipping already-buffered data](https://github.com/rust-osdev/bootloader/pull/550)
* [Fix FAT type detection for large FAT16 volumes](https://github.com/rust-osdev/bootloader/pull/547)
* [Expose FAT partition creation as a separate public function](https://github.com/rust-osdev/bootloader/pull/535)
* [uefi: bump from 0.20 to 0.38](https://github.com/rust-osdev/bootloader/pull/566)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.15...v0.11.16

# 0.11.15 - 2026-02-01

This release is compatible with Rust nightlies starting with `nightly-2026-02-01`.

* [build with -Zjson-target-spec](https://github.com/rust-osdev/bootloader/pull/536)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.14...v0.11.15

# 0.11.14 - 2026-01-13

* [Add kernel stack address to `BootInfo`](https://github.com/rust-osdev/bootloader/pull/531)
* [Fix overflow error during address calculation](https://github.com/rust-osdev/bootloader/pull/530)
* [Add llvm-tools to components in rust-toolchain file](https://github.com/rust-osdev/bootloader/pull/529)
* [Fix links documentation](https://github.com/rust-osdev/bootloader/pull/528)
* [Fix typo in documentation](https://github.com/rust-osdev/bootloader/pull/527)
* [Update rust edition to 2024](https://github.com/rust-osdev/bootloader/pull/526)
* [Fix buffer overlow in `DiskAccess::read_exact_into` for bios](https://github.com/rust-osdev/bootloader/pull/524)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.13...v0.11.14

# 0.11.13 - 2025-11-27

This release is compatible with Rust nightlies starting with `nightly-2025-11-21`.

* [Add basic example](https://github.com/rust-osdev/bootloader/pull/519)
* [Use legacy symbol mangling for BIOS stage 2](https://github.com/rust-osdev/bootloader/pull/522)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.12...v0.11.13

# 0.11.12 - 2025-09-03

This release is compatible with Rust nightlies starting with `nightly-2025-08-28`.

* [Fix: `target-pointer-width` field now expects an integer](https://github.com/rust-osdev/bootloader/pull/516)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.11...v0.11.12

# 0.11.11 – 2025-07-31

This release is compatible with Rust nightlies starting with `nightly-2025-07-24`.

* [Update uart_16550 to 0.3.2](https://github.com/rust-osdev/bootloader/pull/495)
* [add `kernel_base` mapping to the BootloaderConfig](https://github.com/rust-osdev/bootloader/pull/494)
* [Use Result::ok](https://github.com/rust-osdev/bootloader/pull/496)
* [implement Send+Sync for MemoryRegions](https://github.com/rust-osdev/bootloader/pull/502)
* [Document physical memory mapping size](https://github.com/rust-osdev/bootloader/pull/506)
* [Fixes the type of target-c-int-width in target jsons. #](https://github.com/rust-osdev/bootloader/pull/509)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.10...v0.11.11

# 0.11.10 – 2025-02-10

* [Remove "UEFI boot" log message](https://github.com/rust-osdev/bootloader/pull/476)
* [use threads instead of futures in build.rs](https://github.com/rust-osdev/bootloader/pull/484)
* [Move test kernels to a separate workspace](https://github.com/rust-osdev/bootloader/pull/486)
* [fix condition for running bootloader common tests](https://github.com/rust-osdev/bootloader/pull/487)
* [Update `x86_64` to `0.15.2`](https://github.com/rust-osdev/bootloader/pull/490)
* [change rustc-abi in custom targets to x86-softfloat](https://github.com/rust-osdev/bootloader/pull/491)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.9...v0.11.10

# 0.11.9 – 2024-11-30

This release is compatible with Rust nightlies starting with `nightly-2024-11-23`.

* [copy more PML4 entries](https://github.com/rust-osdev/bootloader/pull/466)
* [Convert LF to CRLF when writing to serial port](https://github.com/rust-osdev/bootloader/pull/474)
* [Update x86_64 & fix build on latest nightly](https://github.com/rust-osdev/bootloader/pull/478)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.8...v0.11.9

# 0.11.8 – 2024-11-02

* [avoid 32-bit relocation to __BOOTLOADER_CONFIG](https://github.com/rust-osdev/bootloader/pull/428)
* [Fix doc comment and error message only referencing the BIOS but used for UEFI](https://github.com/rust-osdev/bootloader/pull/439)
* [Ensure all page table frames are mapped as writable](https://github.com/rust-osdev/bootloader/pull/444)
* [Guard the lower 1MB of memory](https://github.com/rust-osdev/bootloader/pull/446)
* [always cover at least the first 4 GiB of physical memory](https://github.com/rust-osdev/bootloader/pull/448)
* [Fixed "jc fail" instructions not working properly and updated README.md](https://github.com/rust-osdev/bootloader/pull/453)
* [Remove 3dnow features from stage4 target](https://github.com/rust-osdev/bootloader/pull/471)
* [mention E820 in docs for UnknownBios](https://github.com/rust-osdev/bootloader/pull/461)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.7...v0.11.8

# 0.11.7 – 2024-02-16

* Set `NO_EXECUTE` flag for all writable memory regions by @phil-opp in https://github.com/rust-osdev/bootloader/pull/409
* adapt data layout to match LLVM's by @tsatke in https://github.com/rust-osdev/bootloader/pull/420

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.6...v0.11.7

# 0.11.6 – 2024-01-28

* [Embed bios and uefi binaries](https://github.com/rust-osdev/bootloader/pull/395)
* [Add a `take` method to `Optional`](https://github.com/rust-osdev/bootloader/pull/411)
* [Fix data layout for stage 3 target](https://github.com/rust-osdev/bootloader/pull/413)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.5...v0.11.6

# 0.11.5 – 2023-12-28

* [RacyCell<T>: Data race allowed on `T`](https://github.com/rust-osdev/bootloader/pull/390)
* [Update license field following SPDX 2.1 license expression standard](https://github.com/rust-osdev/bootloader/pull/391)
* [kernel image fields & zero out rbp](https://github.com/rust-osdev/bootloader/pull/346)
* [Update `rustix` dependency](https://github.com/rust-osdev/bootloader/pull/398)
* [Add an additional MB of space to the generated FAT partition](https://github.com/rust-osdev/bootloader/pull/397)
* [Fix: Enable test runner again](https://github.com/rust-osdev/bootloader/pull/407)
* [Fix: Mark `ramdisk` as used in memory map](https://github.com/rust-osdev/bootloader/pull/408)

**Full Changelog**: https://github.com/rust-osdev/bootloader/compare/v0.11.4...v0.11.5

# 0.11.4 – 2023-07-05

- [Fix bug stemming from treating an exclusive range as an inclusive ranges](https://github.com/rust-osdev/bootloader/pull/362)
- [Update `uefi` dependency to `v0.20`](https://github.com/rust-osdev/bootloader/pull/360)
- [Implemented sorting of uefi memory maps](https://github.com/rust-osdev/bootloader/pull/365)
- [Run `cargo update` to fix build on nightly](https://github.com/rust-osdev/bootloader/pull/385)

# 0.11.3 – 2023-03-26

- [Fix docs.rs build](https://github.com/rust-osdev/bootloader/pull/358)

# 0.11.2 – 2023-03-12

- Fix internal error in Cargo.toml setup that prevented publishing 0.11.1

# 0.11.1 – 2023-03-12

## Features

* [Load ramdisk feature](https://github.com/rust-osdev/bootloader/pull/302)
* [Support higher half position independent kernels](https://github.com/rust-osdev/bootloader/pull/289)
- New `set_boot_config` method to configure the boot process (frame buffer dimensions and log output). This is the result of a set of PRs:
  - [Log level feature](https://github.com/rust-osdev/bootloader/pull/303)
  - [Improve Logging](https://github.com/rust-osdev/bootloader/pull/314)
  - [Add support for a configuration file](https://github.com/rust-osdev/bootloader/pull/326)
  - [Fix loading of boot configuration](https://github.com/rust-osdev/bootloader/pull/342)
  - [Minor improvements to `BootConfig`](https://github.com/rust-osdev/bootloader/pull/349)
- [Add `bios` and `uefi` cargo features](https://github.com/rust-osdev/bootloader/pull/304)
- Boot Info: [Add a `FrameBuffer::into_buffer` method for taking ownership](https://github.com/rust-osdev/bootloader/pull/319)
* [Simplified disk builder](https://github.com/rust-osdev/bootloader/pull/320)

## Fixes
- [Correctly allocate last frame in memory descriptor](https://github.com/rust-osdev/bootloader/pull/316)
- [Correctness fixes for stage2](https://github.com/rust-osdev/bootloader/pull/328)
- [Fix: treat `kernel_slice_end` as an exclusive bound when checking for overlaps](https://github.com/rust-osdev/bootloader/pull/334)
* [Map BIOS stage-4 at lower address to avoid conflicts with the kernel](https://github.com/rust-osdev/bootloader/pull/337)
* [Create kernel stack with correct size and set up a guard page](https://github.com/rust-osdev/bootloader/pull/335)

## Other improvements
- [Implement faster bios builds](https://github.com/rust-osdev/bootloader/pull/324)
- [Remove dependency on `time` crate](https://github.com/rust-osdev/bootloader/pull/332)
- [Fix warnings from Clippy](https://github.com/rust-osdev/bootloader/pull/336)
* [Make a link in the documentation clickable](https://github.com/rust-osdev/bootloader/pull/341)
* [Fix spelling and add a check](https://github.com/rust-osdev/bootloader/pull/340)
* [Run cargo update](https://github.com/rust-osdev/bootloader/pull/347)

# 0.11.0 – 2022-12-01

Major rewrite of the `bootloader` crate with various breaking changes:

- **Separate API crate:** The bootloader is now split into two parts: An API crate to make kernels loadable by the bootloader and the actual bootloader implementation. This makes the build process for kernels much easier and faster.
- **New config system:** Instead of configuring the bootloader via a special table in the `Cargo.toml`, the configuration now happens through a normal Rust struct, which is part of the `entry_point!` macro. The macro then serializes the config struct at compile time and places it in a special ELF output section. The compile time serialization happens through a manually implemented `const fn` of the config struct.
- **Load the kernel at runtime:** The bootloader is now able to load files from FAT partitions at runtime. Thus, we don't need to link the kernel into the bootloader executable anymore. As a result, we don't need to recompile the bootloader on kernel changes anymore. We also load the config at runtime from the kernel's ELF section, which eliminates the second reason for recompiling the bootloader as well.
- **Split into sub-crates:** Since the bootloader build process does not need access to the kernel executable or its `Cargo.toml` anymore, we can build the different parts of the bootloader independently. For example, the BIOS boot sector is now a separate crate, and the UEFI bootloader is too.
- **Library to create disk images:** To create an abstraction the complex build steps of the different bootloader executables, we compile them inside cargo build scripts. At the top level, we provide a `bootloader` _library_ crate, which compiles everything as part of its build script. This library includes functions for creating BIOS and UEFI disk images for a given kernel. These functions can be used e.g. from a builder crate or a build script of the downstream operating system.

See our [migration guides](docs/migration/README.md) for details.

# 0.10.13 – 2022-09-25

- Add dynamic range configuration ([#229](https://github.com/rust-osdev/bootloader/pull/229))
- Fix boot for machines that report memory regions at high physical addresses (see [#259](https://github.com/rust-osdev/bootloader/issues/259))
  - Limit BIOS bootloader's `max_phys_addr` to 4 GiB ([#260](https://github.com/rust-osdev/bootloader/pull/260))
  - fix `get_free_address` for large sizes (0.10) ([#263](https://github.com/rust-osdev/bootloader/pull/263))
  - Only perform a single TLB flush after identity mapping ([#265](https://github.com/rust-osdev/bootloader/pull/265))
- Correct typos in `src/binary/level_4_entries.rs` ([#228](https://github.com/rust-osdev/bootloader/pull/228))

# 0.10.12 – 2022-02-06

- Add support for position independent executables ([#206](https://github.com/rust-osdev/bootloader/pull/206))
- Add optional ASLR ([#221](https://github.com/rust-osdev/bootloader/pull/221))
- Logger: nicer font rendering into framebuffer ([#213](https://github.com/rust-osdev/bootloader/pull/213))
- Fix warnings on latest nightly (`maybe_uninit_extra` is no longer feature-gated) ([#222](https://github.com/rust-osdev/bootloader/pull/222))
- Rework `UsedLevel4Entries` ([#219](https://github.com/rust-osdev/bootloader/pull/219))
- Add small doc-comment to entry_point! macro ([#220](https://github.com/rust-osdev/bootloader/pull/220))

# 0.10.11 – 2022-01-09

- Remove feature flag for `lang_items`, `asm` and `global_asm` ([#210](https://github.com/rust-osdev/bootloader/pull/210))
- Use `set_reg` method of `CS`, `DS`, `ES` and `SS` segment structs ([#211](https://github.com/rust-osdev/bootloader/pull/211))

# 0.10.10 – 2021-12-23

- Fix `asm` imports on latest nightly ([#209](https://github.com/rust-osdev/bootloader/pull/209))

# 0.10.9 – 2021-10-07

- Add support for framebuffer configuration ([#179](https://github.com/rust-osdev/bootloader/pull/179))

# 0.10.8 – 2021-08-22

- Pad UEFI FAT file length ([#180](https://github.com/rust-osdev/bootloader/pull/180))
- Also check cfg gated target field for bootloader dependency ([#182](https://github.com/rust-osdev/bootloader/pull/182)

# 0.10.7 – 2021-08-09

- Fix `relocation-model` field name in the target spec json ([#186](https://github.com/rust-osdev/bootloader/pull/186))
  - This effectively changes the `relocation-model` from `pic` to `static`. Please report if you encounter any issues because of this.
  - This fixes the compilation warnings on the latest nightlies.

# 0.10.6 – 2021-05-24

- Identity-map GDT into kernel address space to fix `iretq` ([#175](https://github.com/rust-osdev/bootloader/pull/175))
- Uefi: Look for an ACPI2 RSDP first ([#174](https://github.com/rust-osdev/bootloader/pull/174))
- Don't check target architecture for builder crate to support cross-compiling ([#176](https://github.com/rust-osdev/bootloader/pull/176))

# 0.10.5 – 2021-05-21

- Fix build on latest Rust nightlies by updating `uefi-rs` dependency ([#170](https://github.com/rust-osdev/bootloader/pull/170))
  - Also: Fix warnings about `.intel_syntax` attribute in assembly code

# 0.10.4 – 2021-05-14

- Fix build on latest Rust nightly by updating to `uefi` v0.9.0 ([#162](https://github.com/rust-osdev/bootloader/pull/162))
- Fix higher half kernels by identity mapping context switch fn earlier ([#161](https://github.com/rust-osdev/bootloader/pull/161))
  - Also: improve reporting of mapping errors

# 0.10.3 – 2021-05-05

- Change register used in setting SS in stage_4 ([#156](https://github.com/rust-osdev/bootloader/pull/156))

# 0.10.2 – 2021-04-30

- Use new `asm!` syntax instead of deprecated `llvm_asm!` ([#154](https://github.com/rust-osdev/bootloader/pull/154))
- Reduce the number of used unstable features of x86_64 crate ([#155](https://github.com/rust-osdev/bootloader/pull/155))

# 0.10.1 – 2021-04-07

- Fix docs.rs build: Don't enable any features

# 0.10.0 – 2021-04-06

- Rewrite for UEFI support ([#130](https://github.com/rust-osdev/bootloader/pull/130))
  - Includes a new build process that no longer uses the `bootimage` crate. See the Readme for details.

# 0.9.19 _(backport) – 2021-08-09

- Set `relocation-model: static` and `panic-strategy: abort` and `fix .intel_syntax` warnings ([#185](https://github.com/rust-osdev/bootloader/pull/185))
  - Fixes warnings on the latest Rust nightlies.
  - This effectively changes the `relocation-model` and `panic-strategy`. Please report if you encounter any issues because of this.

# 0.9.18 _(hotfix)_ – 2021-05-20

- Fix nightly regression by manually passing --gc-sections ([#168](https://github.com/rust-osdev/bootloader/pull/168))

# 0.9.17 _(backport)_ – 2021-04-30

- Reduce the number of used unstable features of x86_64 crate (backport [#155](https://github.com/rust-osdev/bootloader/pull/140))

# 0.9.16 – 2021-03-07

- Replace all remaining `lea`s with `mov` + `offset` ([#140](https://github.com/rust-osdev/bootloader/pull/140))

# 0.9.15 – 2021-03-07

- Fix linker errors on latest nightlies ([#139](https://github.com/rust-osdev/bootloader/pull/139))

# 0.9.14 – 2021-02-24

- Fix "panic message is not a string literal" warning ([#138](https://github.com/rust-osdev/bootloader/pull/138))

# 0.9.13 – 2021-02-24

(accidental release)

# 0.9.12 – 2021-02-02

- Fix build on latest nightly by updating x86_64 to v0.13.2 ([#135](https://github.com/rust-osdev/bootloader/pull/135))

# 0.9.11 – 2020-09-29

- Update `Cargo.lock` to fix nightly breakage ([#129](https://github.com/rust-osdev/bootloader/pull/129))

# 0.9.10 – 2020-09-24

- Update `x86_64` again to version 0.12.1 to fix `const fn`-related build errors on latest nightly

# 0.9.9 – 2020-09-20

- Run `cargo update` to fix build errors of `x86_64` on latest nightly

# 0.9.8 – 2020-07-17

- Enable rlibc dependency only with `binary` feature ([#126](https://github.com/rust-osdev/bootloader/pull/126))

# 0.9.7 – 2020-07-17

- Make bootloader buildable with `-Zbuild-std` ([#125](https://github.com/rust-osdev/bootloader/pull/125))

# 0.9.6 – 2020-07-16

- Change 1st stage int 13h addressing ([#123](https://github.com/rust-osdev/bootloader/pull/123))

# 0.9.5

- Fix warning by renaming `_improper_ctypes_check` functions ([#122](https://github.com/rust-osdev/bootloader/pull/122))

# 0.9.4

- Add recursive_idx for boot info ([#116](https://github.com/rust-osdev/bootloader/pull/116))
- Remove unused feature gates ([#118](https://github.com/rust-osdev/bootloader/pull/118))

# 0.9.3

- Update x86_64 dependency to version 0.11.0 ([#117](https://github.com/rust-osdev/bootloader/pull/117))

# 0.9.2

- **Nightly Breakage:** Use `llvm_asm!` instead of deprecated `asm!` ([#108](https://github.com/rust-osdev/bootloader/pull/108))

# 0.9.1

- SSE feature: remove inline assembly + don't set reserved bits ([#105](https://github.com/rust-osdev/bootloader/pull/105))

# 0.9.0

- **Breaking**: Identity-map complete vga region (0xa0000 to 0xc0000) ([#104](https://github.com/rust-osdev/bootloader/pull/104))

# 0.8.9

- Implement boot-info-address ([#101](https://github.com/rust-osdev/bootloader/pull/101))

# 0.8.8

- Add basic support for ELF thread local storage segments ([#96](https://github.com/rust-osdev/bootloader/pull/96))

# 0.8.7

- Fix docs.rs build (see commit 01671dbe449b85b3c0ea73c5796cc8f9661585ee)

# 0.8.6

- Objcopy replaces `.` chars with `_` chars ([#94](https://github.com/rust-osdev/bootloader/pull/94))

# 0.8.5

- Update x86_64 dependency ([#92](https://github.com/rust-osdev/bootloader/pull/92))

# 0.8.4

- Move architecture checks from build script into lib.rs ([#91](https://github.com/rust-osdev/bootloader/pull/91))

# 0.8.3

- Remove unnecessary `extern C` on panic handler to fix not-ffi-safe warning ([#85](https://github.com/rust-osdev/bootloader/pull/85))

# 0.8.2

- Change the way the kernel entry point is called to honor alignment ABI ([#81](https://github.com/rust-osdev/bootloader/pull/81))

# 0.8.1

- Add a Cargo Feature for Enabling SSE ([#77](https://github.com/rust-osdev/bootloader/pull/77))

# 0.8.0

- **Breaking**: Parse bootloader configuration from kernel's Cargo.toml ([#73](https://github.com/rust-osdev/bootloader/pull/73))
    - At least version 0.7.7 of `bootimage` is required now.
- Configurable kernel stack size, better non-x86_64 errors ([#72](https://github.com/rust-osdev/bootloader/pull/72))
- Dynamically map kernel stack, boot info, physical memory and recursive table ([#71](https://github.com/rust-osdev/bootloader/pull/71))

# 0.7.1

- Run cargo update (improves compile times because of trimmed down upstream dependencies)

# 0.7.0

- **Breaking**: Only include dependencies when `binary` feature is enabled ([#68](https://github.com/rust-osdev/bootloader/pull/68))
    - For manual builds, the `binary` feature must be enabled when building
    - For builds using `bootimage`, at least version 0.7.6 of `bootimage` is required now.

# 0.6.4

- Use volatile accesses in VGA code and make font dependency optional ([#67](https://github.com/rust-osdev/bootloader/pull/67))
  - Making the dependency optional should improve compile times when the VGA text mode is used.

# 0.6.3

- Update CI badge, use latest version of x86_64 crate and rustfmt ([#63](https://github.com/rust-osdev/bootloader/pull/63))

# 0.6.2

- Remove stabilized publish-lockfile feature ([#62](https://github.com/rust-osdev/bootloader/pull/62))

# 0.6.1

- Make the physical memory offset configurable through a `BOOTLOADER_PHYSICAL_MEMORY_OFFSET` environment variable ([#58](https://github.com/rust-osdev/bootloader/pull/58)).
- Use a stripped copy of the kernel binary (debug info removed) to reduce load times ([#59](https://github.com/rust-osdev/bootloader/pull/59)).

# 0.6.0

- **Breaking**: Don't set the `#[cfg(not(test))]` attribute for the entry point function in the `entry_point` macro
    - With custom test frameworks, it's possible to use the normal entry point also in test environments
    - To get the old behavior, you can add the `#[cfg(not(test))]` attribute to the `entry_point` invocation
- Additional assertions for the passed `KERNEL` executable
    - check that the executable exists (for better error messages)
    - check that the executable has a non-empty text section (an empty text section occurs when no entry point is set)

# 0.5.3

- Mention minimal required bootimage version in error message when `KERNEL` environment variable is not set.

# 0.5.2

- Remove redundant import that caused a warning

# 0.5.1

- Add a `package.metadata.bootloader.target` key to the Cargo.toml that can be used by tools such as `bootimage`.

# 0.5.0

- **Breaking**: Change the build system: Use a build script that expects a `KERNEL` environment variable instead of using a separate `builder` executable as before. See [#51](https://github.com/rust-osdev/bootloader/pull/51) and [#53](https://github.com/rust-osdev/bootloader/pull/53) for more information.
  - This makes the bootloader incompatible with versions `0.6.*` and earlier of the `bootimage` tool.
  - The bootloader also requires the `llvm-tools-preview` rustup component now.

# 0.4.0

## Breaking

- The level 4 page table is only recursively mapped if the `recursive_page_table` feature is enabled.
- Rename `BootInfo::p4_table_addr` to `BootInfo::recursive_page_table_addr` (only present if the cargo feature is enabled)
- Remove `From<PhysFrameRange>` implementations for x86_64 `FrameRange`
  - This only works when the versions align, so it is not a good general solution.
- Remove unimplemented `BootInfo::package` field.
- Make `BootInfo` non-exhaustive so that we can add additional fields later.

## Other

- Add a `map_physical_memory` feature that maps the complete physical memory to the virtual address space at `BootInfo::physical_memory_offset`.
- Re-export `BootInfo` at the root.
