// Keep the migration implementation next to the `log.rs` module while the
// repository still supports the flat source layout used by older checkouts.
include!("../migration.rs");
