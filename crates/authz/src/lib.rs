pub mod error;
#[cfg(feature = "vera")]
pub mod vera;
pub mod request;
#[cfg(feature = "startup")]
pub mod startup;
pub mod r#trait;

#[cfg(feature = "vera-go")]
pub mod vera_go;

// Available only when the `test-helpers` feature is enabled (typically in tests).
#[cfg(feature = "test-helpers")]
pub mod dummy;

#[cfg(feature = "vera-go")]
pub use vera_go::VeraGoAuth as AuthzImpl;

// `AuthzFactoryImpl` is what the node's services composer builds against —
// one build selects exactly one implementation at compile time. `AuthzImpl`
// above remains for tests/tooling that construct a backend directly without
// going through the startup lifecycle.
//
// Selection is gated on `select-vera`/`select-vera-go`, not plainly on
// `vera`/`vera-go`: other crates in this workspace (`cli-tool`, for its
// always-on chain-admin functionality) legitimately need both the `vera`
// and `vera-go` modules compiled into the same binary for their own direct use
// of `VeraAuth`/`VeraGoAuth`, without that implying anything about which
// one orbis-node's own services composer should treat as canonical. Only
// the binary actually selecting a factory (orbis-node) turns on a
// `select-*` feature.
#[cfg(all(feature = "select-vera", feature = "select-vera-go"))]
compile_error!(
    "Features 'select-vera' and 'select-vera-go' are mutually exclusive for AuthzFactoryImpl."
);

#[cfg(feature = "select-vera")]
pub use vera::startup::VeraAuthzFactory as AuthzFactoryImpl;
#[cfg(feature = "select-vera-go")]
pub use vera_go::startup::VeraGoAuthzFactory as AuthzFactoryImpl;
