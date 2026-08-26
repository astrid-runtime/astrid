# UEFI Bootloader for `x86_64`

## Build

```
cargo b --target x86_64-unknown-uefi --release -Zbuild-std=core -Zbuild-std-features=compiler-builtins-mem
```
