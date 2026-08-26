//! Provides the interface to make kernels compatible with the
//! [**`bootloader`**](https://docs.rs/bootloader/latest/bootloader/) crate.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub use self::{config::BootloaderConfig, info::BootInfo};

/// Allows to configure the system environment set up by the bootloader.
pub mod config;
/// Contains the boot information struct sent by the bootloader to the kernel on startup.
pub mod info;

mod concat {
    include!(concat!(env!("OUT_DIR"), "/concat.rs"));
}

mod version_info {
    include!(concat!(env!("OUT_DIR"), "/version_info.rs"));
}

/// Defines the entry point function.
///
/// The function must have the signature `fn(&'static mut BootInfo) -> !`.
///
/// This macro just creates a function named `_start`, which the linker will use as the entry
/// point. The advantage of using this macro instead of providing an own `_start` function is
/// that the macro ensures that the function and argument types are correct.
///
/// ## Configuration
///
/// This macro supports an optional second parameter to configure how the bootloader should
/// boot the kernel. The second parameter needs to be given as `config = ...` and be of type
/// [`&BootloaderConfig`](crate::BootloaderConfig). If not given, the configuration defaults to
/// [`BootloaderConfig::new_default`](crate::BootloaderConfig::new_default).
///
/// ## Examples
///
/// - With default configuration:
///
///   ```no_run
///   #![no_std]
///   #![no_main]
///   # #![feature(lang_items)]
///
///   bootloader_api::entry_point!(main);
///
///   fn main(bootinfo: &'static mut bootloader_api::BootInfo) -> ! {
///       loop {}
///   }
///
///   #[panic_handler]
///   fn panic(_info: &core::panic::PanicInfo) -> ! {
///       loop {}
///   }
///
///   # #[lang = "eh_personality"] fn eh_personality() {} // not needed when disabling unwinding
///   ```
///
///   The name of the entry point function does not matter. For example, instead of `main`, we
///   could also name it `fn my_entry_point(...) -> !`. We would then need to specify
///   `entry_point!(my_entry_point)` of course.
///
/// - With custom configuration:
///
///   ```no_run
///   #![no_std]
///   #![no_main]
///   # #![feature(lang_items)]
///
///   use bootloader_api::{entry_point, BootloaderConfig};
///
///   pub static BOOTLOADER_CONFIG: BootloaderConfig = {
///       let mut config = BootloaderConfig::new_default();
///       config.kernel_stack_size = 90 * 1024;
///       config
///   };
///
///   entry_point!(main, config = &BOOTLOADER_CONFIG);
///
///   fn main(bootinfo: &'static mut bootloader_api::BootInfo) -> ! {
///       loop {}
///   }
///
///   #[panic_handler]
///   fn panic(_info: &core::panic::PanicInfo) -> ! {
///       loop {}
///   }
///
///   # #[lang = "eh_personality"] fn eh_personality() {} // not needed when disabling unwinding
///   ```
///
/// ## Implementation Notes
///
/// - **Start function:** The `entry_point` macro generates a small wrapper function named
///   `_start` (without name mangling) that becomes the actual entry point function of the
///   executable. This function doesn't do anything itself, it just calls into the function
///   that is provided as macro argument. The purpose of this function is to use the correct
///   ABI and parameter types required by this crate. A user-provided `_start` function could
///   silently become incompatible on dependency updates since the Rust compiler cannot
///   check the signature of custom entry point functions.
/// - **Configuration:** Behind the scenes, the configuration struct is serialized using
///   [`BootloaderConfig::serialize`](crate::BootloaderConfig::serialize). The resulting byte
///   array is then stored as a static variable annotated with
///   `#[link_section = ".bootloader-config"]`, which instructs the Rust compiler to store it
///   in a special section of the resulting ELF executable. From there, the bootloader will
///   automatically read it when loading the kernel.
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! entry_point {
    ($path:path) => {
        $crate::entry_point!($path, config = &$crate::BootloaderConfig::new_default());
    };
    ($path:path, config = $config:expr) => {
        const _: () = {
            #[unsafe(link_section = ".bootloader-config")]
            pub static __BOOTLOADER_CONFIG: [u8; $crate::BootloaderConfig::SERIALIZED_LEN] = {
                // validate the type
                let config: &$crate::BootloaderConfig = $config;
                config.serialize()
            };

            // Workaround for https://github.com/rust-osdev/bootloader/issues/427
            static __BOOTLOADER_CONFIG_REF: &[u8; $crate::BootloaderConfig::SERIALIZED_LEN] =
                &__BOOTLOADER_CONFIG;

            #[unsafe(export_name = "_start")]
            pub extern "C" fn __impl_start(boot_info: &'static mut $crate::BootInfo) -> ! {
                // validate the signature of the program entry point
                let f: fn(&'static mut $crate::BootInfo) -> ! = $path;

                // ensure that the config is used so that the linker keeps it
                $crate::__force_use(&__BOOTLOADER_CONFIG_REF);

                f(boot_info)
            }
        };
    };
}

#[doc(hidden)]
#[cfg(target_arch = "x86_64")]
pub fn __force_use(slice: &&[u8; BootloaderConfig::SERIALIZED_LEN]) {
    let force_use = slice as *const _ as usize;
    unsafe { core::arch::asm!("add {0}, 0", in(reg) force_use, options(nomem, nostack)) };
}
