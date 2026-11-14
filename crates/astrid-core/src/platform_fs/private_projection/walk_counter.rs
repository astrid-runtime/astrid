//! Test-only accounting of absolute directory ancestry walks.

thread_local! {
    static DIRECTORY_WALK_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(in crate::platform_fs) fn record() {
    DIRECTORY_WALK_COUNT.with(|count| count.set(count.get().strict_add(1)));
}

pub(crate) fn reset_directory_walk_count() {
    DIRECTORY_WALK_COUNT.set(0);
}

pub(crate) fn directory_walk_count() -> usize {
    DIRECTORY_WALK_COUNT.get()
}
