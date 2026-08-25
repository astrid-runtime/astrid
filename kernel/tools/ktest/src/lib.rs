//! Host-side combined boot ktest helpers. Ring 0 stays in
//! `astrid-native-kernel`. Signing stays in `astrid-native-closure` on the
//! loader path. Trust policy is compiled public keys, not table-chosen keys.

pub mod determinism;
pub mod events;
pub mod firmware;
pub mod image;
pub mod machine;
