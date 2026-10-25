//! Thread-local observation of the actual traversal output sink, not allocations
//! made by object loading or the bounded `FastCDC` previous-chunk window.

use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OutputBytes {
    pub(crate) reserved: usize,
    pub(crate) written: usize,
}

thread_local! {
    static OUTPUT: Cell<Option<OutputBytes>> = const { Cell::new(None) };
}

struct Restore(Option<OutputBytes>);
impl Drop for Restore {
    fn drop(&mut self) {
        OUTPUT.set(self.0);
    }
}

pub(crate) fn measure<T>(operation: impl FnOnce() -> T) -> (T, OutputBytes) {
    let _restore = Restore(OUTPUT.replace(Some(OutputBytes::default())));
    let result = operation();
    (result, OUTPUT.get().unwrap())
}

pub(super) fn observe(reserved: usize, written: usize) {
    if let Some(mut total) = OUTPUT.get() {
        total.reserved = total.reserved.strict_add(reserved);
        total.written = total.written.strict_add(written);
        OUTPUT.set(Some(total));
    }
}
