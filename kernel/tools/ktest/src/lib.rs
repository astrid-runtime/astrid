//! Host-side M1 and dual-closure ktest helpers. Ring 0 stays in
//! `astrid-native-kernel`. Signing stays in `astrid-native-closure` on the
//! loader path.

pub mod determinism;
pub mod events;
pub mod firmware;
pub mod image;
pub mod machine;
