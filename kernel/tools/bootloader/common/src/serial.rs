use core::fmt;
use uart_16550::backend::PioBackend;

// TODO this type can be replaced with Uart16550Tty but using it currently panics
// in the new constructor.
pub struct SerialPort {
    port: uart_16550::Uart16550<PioBackend>,
}

impl SerialPort {
    /// # Safety
    ///
    /// unsafe because this function must only be called once
    pub unsafe fn init() -> Self {
        let mut port =
            unsafe { uart_16550::Uart16550::new_port(0x3F8) }.expect("should be valid port");
        port.init(uart_16550::Config::default())
            .expect("should init successfully");
        Self { port }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for char in s.bytes() {
            match char {
                b'\n' => self.port.send_bytes_exact(b"\r\n"),
                byte => self.port.send_bytes_exact(&[byte]),
            }
        }
        Ok(())
    }
}
