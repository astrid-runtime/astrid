#![no_std]

use serde::{Deserialize, Serialize};

/// Configures the boot behavior of the bootloader.
#[derive(Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct BootConfig {
    /// Configuration for the frame buffer setup.
    pub frame_buffer: FrameBuffer,

    /// The minimum log level that is printed to the screen during boot.
    ///
    /// The default is [`LevelFilter::Trace`].
    pub log_level: LevelFilter,

    /// Whether the bootloader should print log messages to the framebuffer during boot.
    ///
    /// Enabled by default.
    pub frame_buffer_logging: bool,

    /// Whether the bootloader should print log messages to the serial port during boot.
    ///
    /// Enabled by default.
    pub serial_logging: bool,

    #[doc(hidden)]
    pub _test_sentinel: u64,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            frame_buffer: Default::default(),
            log_level: Default::default(),
            frame_buffer_logging: true,
            serial_logging: true,
            _test_sentinel: 0,
        }
    }
}

/// Configuration for the frame buffer used for graphical output.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct FrameBuffer {
    /// Instructs the bootloader to set up a framebuffer format that has at least the given height.
    ///
    /// If this is not possible, the bootloader will fall back to a smaller format.
    pub minimum_framebuffer_height: Option<u64>,
    /// Instructs the bootloader to set up a framebuffer format that has at least the given width.
    ///
    /// If this is not possible, the bootloader will fall back to a smaller format.
    pub minimum_framebuffer_width: Option<u64>,
}

/// An enum representing the available verbosity level filters of the logger.
///
/// Based on
/// <https://github.com/rust-lang/log/blob/dc32ab999f52805d5ce579b526bd9d9684c38d1a/src/lib.rs#L552-565>
#[derive(
    Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
pub enum LevelFilter {
    /// A level lower than all log levels.
    Off,
    /// Corresponds to the `Error` log level.
    Error,
    /// Corresponds to the `Warn` log level.
    Warn,
    /// Corresponds to the `Info` log level.
    Info,
    /// Corresponds to the `Debug` log level.
    Debug,
    /// Corresponds to the `Trace` log level.
    #[default]
    Trace,
}
