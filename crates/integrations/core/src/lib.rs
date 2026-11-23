//! Shared operation and authentication evidence model for Orbis flows.
//!
//! Scaffold only: no public API is implemented.
//!
//! This crate will describe the requested operation, portable evidence, and the
//! result of local verification. Verification results are local to their verifier;
//! the original evidence must still reach every participating Orbis node.
//!
//! ACP permission evaluation and threshold cryptography belong to their existing
//! layers. Add shared types as the reference applications establish their needs.
