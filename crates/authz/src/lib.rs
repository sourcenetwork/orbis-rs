pub mod error;
#[cfg(feature = "native")]
pub mod native;
pub mod request;
#[cfg(feature = "startup")]
pub mod startup;
pub mod r#trait;

#[cfg(feature = "vera")]
pub mod vera;

// Available only when the `test-helpers` feature is enabled (typically in tests).
#[cfg(feature = "test-helpers")]
pub mod dummy;

#[cfg(feature = "vera")]
pub use vera::VeraAuth as AuthzImpl;

// `AuthzFactoryImpl` is what the node's services composer builds against —
// one build selects exactly one implementation at compile time. `AuthzImpl`
// above remains for tests/tooling that construct a backend directly without
// going through the startup lifecycle.
//
// Selection is gated on `select-native`/`select-vera`, not plainly on
// `native`/`vera`: other crates in this workspace (`cli-tool`, for its
// always-on chain-admin functionality) legitimately need both the `native`
// and `vera` modules compiled into the same binary for their own direct use
// of `AuthzImpl`/`NativeAuth`, without that implying anything about which
// one orbis-node's own services composer should treat as canonical. Only
// the binary actually selecting a factory (orbis-node) turns on a
// `select-*` feature.
#[cfg(all(feature = "select-native", feature = "select-vera"))]
compile_error!(
    "Features 'select-native' and 'select-vera' are mutually exclusive for AuthzFactoryImpl."
);

#[cfg(feature = "select-native")]
pub use native::startup::NativeAuthzFactory as AuthzFactoryImpl;
#[cfg(feature = "select-vera")]
pub use vera::startup::VeraAuthzFactory as AuthzFactoryImpl;
