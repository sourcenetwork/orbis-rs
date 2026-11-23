//! Passkey and FIDO2 security-key integration for Orbis flows.
//!
//! Scaffold only: enrollment and authentication are not implemented.
//!
//! This crate will connect WebAuthn enrollment and request-bound authentication
//! evidence to the shared Orbis operation model. Both passkey and FIDO2 YubiKey
//! examples use this integration.
//!
//! Browser interaction, credential persistence, and application routing belong
//! to the host application or its adapters. Node-side verification must use
//! independently trusted credential and request context.
