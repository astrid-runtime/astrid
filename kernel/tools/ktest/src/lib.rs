//! Host-side combined boot ktest helpers. Ring 0 stays in
//! `astrid-native-kernel`; explicit fixture key files are consumed by the
//! loader path. Root policy and boot-context expectations are never selected
//! from untrusted table headers.

pub mod determinism;
pub mod events;
pub mod firmware;
pub mod image;
pub mod machine;
