//! DKIM email evidence integration for Orbis flows.
//!
//! Scaffold only: challenge construction and proof verification are not implemented.
//!
//! This crate will bind signed email evidence to an exact Orbis operation and
//! verify it against an explicitly trusted DKIM-key source.
//!
//! Mail delivery, reply capture, key-registry updates, and application routing
//! belong to adapters. An arbitrary DNS answer or actor string is not treated
//! as authenticated evidence. Principal mapping into ACP remains to be designed.
