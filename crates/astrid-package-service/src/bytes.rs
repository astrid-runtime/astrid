macro_rules! opaque32 {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Creates an identifier from exactly 32 canonical bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the immutable canonical bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Returns ownership of the immutable canonical bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }
    };
}

opaque32!(
    PrincipalUid,
    "Immutable effective principal identity stamped by authenticated ingress."
);
opaque32!(
    RecoveryToken,
    "Opaque token used to locate recovery evidence without granting authority."
);
