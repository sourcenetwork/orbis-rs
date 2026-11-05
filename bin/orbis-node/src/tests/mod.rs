//! Library tests.
//!
//! Unit tests such as `node` stay outside the integration-test gate. The
//! Docker scenarios live in `e2e` and are compiled only with that feature.

mod node;

#[cfg(feature = "scale-testing")]
mod scale_testing;

#[cfg(feature = "integration-test")]
mod e2e;
