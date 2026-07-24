//! I/O error context which retains the original native error as its source.

use std::fmt;
use std::io;

#[cfg(test)]
use std::error::Error as _;

#[derive(Debug)]
struct ContextualIoError {
    context: String,
    source: io::Error,
}

impl fmt::Display for ContextualIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.context, self.source)
    }
}

impl std::error::Error for ContextualIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub(super) fn with_context(error: io::Error, context: impl Into<String>) -> io::Error {
    io::Error::new(
        error.kind(),
        ContextualIoError {
            context: context.into(),
            source: error,
        },
    )
}

#[cfg(test)]
pub(super) fn native_error_code(error: &io::Error) -> Option<i32> {
    if let Some(code) = error.raw_os_error() {
        return Some(code);
    }
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<io::Error>()
            && let Some(code) = error.raw_os_error()
        {
            return Some(code);
        }
        if let Some(contextual) = current.downcast_ref::<ContextualIoError>()
            && let Some(code) = native_error_code(&contextual.source)
        {
            return Some(code);
        }
        source = current.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_preserves_native_error_source() {
        let error = with_context(
            io::Error::from_raw_os_error(5),
            "private transaction commit",
        );
        assert_eq!(native_error_code(&error), Some(5));
        assert!(error.to_string().contains("private transaction commit"));
    }
}
