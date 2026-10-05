//! Minimal Jubjub FROST Schnorr verification, compiled to `wasm32-unknown-unknown`
//! and called from Go (vera) via a pure-Go WASM runtime (no cgo, no Rust
//! toolchain required on the Go side).
//!
//! Deliberately depends only on `jubjub`+`group`+`sha2` (not `crates/crypto`):
//! `crates/crypto`'s `rand_core`-based randomness (needed elsewhere for
//! signing, never for verification) pulls in `getrandom`, which does not
//! compile for `wasm32-unknown-unknown` without extra configuration this
//! crate has no reason to carry. `verify_core`/`compute_challenge` below
//! mirror `crates/crypto/src/jubjub/sign.rs`'s `ThresholdJubjubSigner::verify`
//! and `compute_challenge` exactly, calling zkcrypto's native `jubjub` types
//! directly so the generator, encoding, and challenge transcript are
//! byte-for-byte the same as the Rust signing side — not a reimplementation
//! of curve math, just this crate's own copy of the ~15-line FROST transcript.

use group::{Group, GroupEncoding};
use jubjub::{Fr, SubgroupPoint};
use sha2::{Digest, Sha512};

/// Must match `crates/crypto/src/jubjub/sign.rs`'s `FROST_CHALLENGE_DOMAIN`.
const FROST_CHALLENGE_DOMAIN: &[u8] = b"FROST-jubjub-challenge";
/// Test-fixture-only domain; never used by `verify_core`. Distinct from the
/// above so a test signature's transcript can never collide with a
/// production one.
const TEST_NONCE_DOMAIN: &[u8] = b"jubjub-wasm-test-nonce-v1";

fn compute_challenge(r_bytes: &[u8; 32], pk_bytes: &[u8; 32], msg: &[u8]) -> Fr {
    let mut hasher = Sha512::new();
    hasher.update(FROST_CHALLENGE_DOMAIN);
    hasher.update(r_bytes);
    hasher.update(pk_bytes);
    hasher.update(msg);
    let digest: [u8; 64] = hasher.finalize().into();
    Fr::from_bytes_wide(&digest)
}

fn decode_point(bytes: &[u8]) -> Option<SubgroupPoint> {
    let arr: &[u8; 32] = bytes.try_into().ok()?;
    SubgroupPoint::from_bytes(arr).into()
}

fn decode_scalar(bytes: &[u8]) -> Option<Fr> {
    let arr: &[u8; 32] = bytes.try_into().ok()?;
    Fr::from_bytes(arr).into()
}

/// `z*G == R + c*Y`. Returns `false` for any malformed input or identity
/// public key — never panics on attacker-controlled bytes (no unwrap/expect
/// on anything decoded from `pk_bytes`/`msg`/`sig_bytes`).
pub fn verify_core(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    if pk_bytes.len() != 32 || sig_bytes.len() != 64 {
        return false;
    }
    let (r_bytes, z_bytes) = sig_bytes.split_at(32);
    let Some(pk) = decode_point(pk_bytes) else {
        return false;
    };
    let Some(r_point) = decode_point(r_bytes) else {
        return false;
    };
    let Some(z) = decode_scalar(z_bytes) else {
        return false;
    };
    // The identity makes the discrete-log statement vacuous (0 = 0*G): any
    // (R, z) with the right shape trivially verifies against it, without the
    // "signer" knowing anything. Mirrors orbis-rs's own explicit check.
    if pk == SubgroupPoint::identity() {
        return false;
    }

    let r_arr: [u8; 32] = r_bytes.try_into().unwrap();
    let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
    let c = compute_challenge(&r_arr, &pk_arr, msg);

    SubgroupPoint::generator() * z == r_point + pk * c
}

/// `true` iff `pk_bytes` decodes to the identity point. `false` for any
/// malformed encoding too — this is a pre-check used before `verify_core`,
/// not a general-purpose decode; a bytes string that fails to decode is
/// handled elsewhere (by `verify_core` itself returning `false`).
pub fn is_identity_pubkey_core(pk_bytes: &[u8]) -> bool {
    matches!(decode_point(pk_bytes), Some(p) if p == SubgroupPoint::identity())
}

/// Test-fixture helper: `x*G`. Not used by `verify_core`; exists only so
/// Go-side tests can derive a public key from an arbitrary secret scalar
/// chosen at test-run time, via the same Jubjub implementation `verify_core`
/// checks against (zero risk of a second, divergent implementation).
pub fn derive_public_key_core(secret_bytes: &[u8]) -> Option<[u8; 32]> {
    let secret = decode_scalar(secret_bytes)?;
    Some((SubgroupPoint::generator() * secret).to_bytes())
}

/// Test-fixture helper: a deterministic-nonce Schnorr signature over an
/// arbitrary message chosen at test-run time. The nonce is derived from
/// `secret_bytes`/`msg` via SHA-512 rather than sampled — `wasm32-unknown-
/// unknown` has no OS entropy source, and test fixtures don't need one
/// (determinism is actually preferable for reproducible tests). Never used
/// in production: `verify_core` has no signing counterpart in this crate.
pub fn test_sign_core(secret_bytes: &[u8], pk_bytes: &[u8], msg: &[u8]) -> Option<[u8; 64]> {
    let secret = decode_scalar(secret_bytes)?;
    let pk_arr: [u8; 32] = pk_bytes.try_into().ok()?;

    let mut hasher = Sha512::new();
    hasher.update(TEST_NONCE_DOMAIN);
    hasher.update(secret_bytes);
    hasher.update(msg);
    let digest: [u8; 64] = hasher.finalize().into();
    let nonce = Fr::from_bytes_wide(&digest);

    let r_bytes = (SubgroupPoint::generator() * nonce).to_bytes();
    let c = compute_challenge(&r_bytes, &pk_arr, msg);
    let z = nonce + c * secret;

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_bytes);
    out[32..].copy_from_slice(&z.to_bytes());
    Some(out)
}

// ============================================================================
// WASM exports
//
// Fixed-layout static buffer protocol: every input/output here is small and
// bounded (32/64 bytes, plus a variable-length message), so a real bump
// allocator would be needless complexity. The Go host writes inputs into
// `BUF` at the fixed offsets documented per function, then calls the export;
// outputs are written back into `BUF` starting at offset 0 once every input
// has already been read into an owned local value (so overlapping input and
// output offsets is safe — nothing reads `BUF` again after it starts being
// overwritten). `buf_ptr()` lets the host discover the address without
// hardcoding it.
//
// Every export wraps its body in `catch_unwind` and converts any panic into
// the same "reject" return value a malformed input would produce. This is
// defense in depth on top of `verify_core`/etc. already being panic-free on
// attacker-controlled bytes by construction (no unwrap/expect on decoded
// data) — belt and suspenders for code a chain's consensus path depends on.
// ============================================================================

// Generous headroom for real protocol messages (serialized ring/report
// payloads can run well past a few hundred bytes) while staying a simple
// fixed-size static buffer — see the module doc comment above for why a
// real allocator isn't used here.
const BUF_LEN: usize = 65536;
static mut BUF: [u8; BUF_LEN] = [0u8; BUF_LEN];

#[no_mangle]
pub extern "C" fn buf_ptr() -> *mut u8 {
    (&raw mut BUF).cast()
}

#[no_mangle]
pub extern "C" fn buf_len() -> u32 {
    BUF_LEN as u32
}

fn with_buf<T>(f: impl FnOnce(&[u8]) -> T + std::panic::UnwindSafe) -> std::thread::Result<T> {
    // Copy out of the static before entering catch_unwind: a `&'static mut`
    // reference to a `static mut` is not itself unwind-safe to close over,
    // and this keeps every export's closure operating on plain owned bytes.
    let snapshot: [u8; BUF_LEN] = unsafe { BUF };
    std::panic::catch_unwind(move || f(&snapshot))
}

/// `BUF[0..32]` = public key, `BUF[32..96]` = signature (R||z),
/// `BUF[96..96+msg_len]` = message. Returns `1` (valid), `0` (invalid or
/// malformed input), or `-1` (internal panic, caught — should be
/// unreachable given `verify_core`'s panic-free construction, but the chain
/// must never trap on attacker-controlled bytes regardless).
#[no_mangle]
pub extern "C" fn verify(msg_len: u32) -> i32 {
    let msg_len = msg_len as usize;
    // `usize` is 32 bits on wasm32-unknown-unknown: compute the end index
    // via checked_add so a msg_len near u32::MAX can't wrap the addition
    // and slip past the length check below (release builds don't panic on
    // overflow) — reject it the same as any other malformed input instead.
    let Some(msg_end) = 96usize.checked_add(msg_len) else {
        return 0;
    };
    match with_buf(move |buf| {
        if msg_end > buf.len() {
            return false;
        }
        verify_core(&buf[0..32], &buf[96..msg_end], &buf[32..96])
    }) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

/// `BUF[0..32]` = public key. Returns `1` (is the identity), `0` (is not, or
/// malformed), `-1` (internal panic, caught).
#[no_mangle]
pub extern "C" fn is_identity_pubkey() -> i32 {
    match with_buf(|buf| is_identity_pubkey_core(&buf[0..32])) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

/// Test-only. `BUF[0..32]` = secret scalar. On success writes the 32-byte
/// public key to `BUF[0..32]` and returns `32`; returns `0` for a malformed
/// secret, `-1` on a caught panic.
#[no_mangle]
pub extern "C" fn derive_public_key() -> i32 {
    let result = with_buf(|buf| derive_public_key_core(&buf[0..32]));
    match result {
        Ok(Some(pk)) => {
            unsafe { BUF[..32].copy_from_slice(&pk) };
            32
        }
        Ok(None) => 0,
        Err(_) => -1,
    }
}

/// Test-only. `BUF[0..64]` = arbitrary seed bytes (wide reduction input, the
/// same operation `Fr::from_bytes_wide` performs throughout production
/// code). On success writes the canonical 32-byte reduced scalar to
/// `BUF[0..32]` and returns `32`. Exists so Go test helpers can turn an
/// arbitrary test seed into a valid secret scalar without this crate
/// exposing the raw scalar-order constant to Go at all.
#[no_mangle]
pub extern "C" fn reduce_scalar_wide() -> i32 {
    let result = with_buf(|buf| {
        let arr: [u8; 64] = buf[0..64].try_into().unwrap();
        Fr::from_bytes_wide(&arr).to_bytes()
    });
    match result {
        Ok(reduced) => {
            unsafe { BUF[..32].copy_from_slice(&reduced) };
            32
        }
        Err(_) => -1,
    }
}

/// Test-only. `BUF[0..32]` = secret scalar, `BUF[32..64]` = public key,
/// `BUF[64..64+msg_len]` = message. On success writes the 64-byte signature
/// to `BUF[0..64]` and returns `64`; returns `0` for malformed input, `-1`
/// on a caught panic.
#[no_mangle]
pub extern "C" fn test_sign(msg_len: u32) -> i32 {
    let msg_len = msg_len as usize;
    // See verify()'s matching comment: checked_add avoids wrapping the end
    // index on wasm32's 32-bit usize for a near-u32::MAX msg_len.
    let Some(msg_end) = 64usize.checked_add(msg_len) else {
        return 0;
    };
    let result = with_buf(move |buf| {
        if msg_end > buf.len() {
            return None;
        }
        test_sign_core(&buf[0..32], &buf[32..64], &buf[64..msg_end])
    });
    match result {
        Ok(Some(sig)) => {
            unsafe { BUF[..64].copy_from_slice(&sig) };
            64
        }
        Ok(None) => 0,
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(scalar: u64) -> SubgroupPoint {
        SubgroupPoint::generator() * Fr::from(scalar)
    }

    #[test]
    fn verify_core_accepts_a_genuine_signature_and_rejects_a_mutated_message() {
        let secret_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 7;
            b
        };
        let secret = decode_scalar(&secret_bytes).unwrap();
        let pk_bytes = (SubgroupPoint::generator() * secret).to_bytes();
        let msg = b"hello jubjub-wasm";

        let sig = test_sign_core(&secret_bytes, &pk_bytes, msg).unwrap();
        assert!(verify_core(&pk_bytes, msg, &sig));
        assert!(!verify_core(&pk_bytes, b"different message", &sig));
    }

    #[test]
    fn verify_core_rejects_malformed_lengths() {
        assert!(!verify_core(&[0u8; 31], b"m", &[0u8; 64]));
        assert!(!verify_core(&[0u8; 32], b"m", &[0u8; 63]));
    }

    #[test]
    fn verify_and_test_sign_reject_an_out_of_range_msg_len_without_panicking() {
        // A msg_len that alone already exceeds BUF_LEN must be rejected by
        // the length check, not just by (coincidentally) panicking on a
        // malformed slice range.
        assert_eq!(verify(BUF_LEN as u32), 0);
        assert_eq!(test_sign(BUF_LEN as u32), 0);

        // msg_len near u32::MAX: offset + msg_len must not wrap back into
        // range on a 32-bit usize target and slip past the check.
        assert_eq!(verify(u32::MAX), 0);
        assert_eq!(test_sign(u32::MAX), 0);
        assert_eq!(verify(u32::MAX - 50), 0); // would wrap to a tiny, in-range value if unchecked
    }

    #[test]
    fn verify_core_rejects_non_canonical_point_and_scalar_encodings() {
        let scalar_modulus_plus_one = {
            // Fr's modulus bytes with the low limb bumped by one — definitely
            // out of range, regardless of the exact modulus value.
            let mut b = [0xffu8; 32];
            b[31] = 0x7f; // keep the top bit clear; still far above the ~2^252 modulus
            b
        };
        assert!(decode_scalar(&scalar_modulus_plus_one).is_none());
        assert!(!verify_core(&[0u8; 32], b"m", &[0u8; 64])); // all-zero pk decodes to identity anyway, but exercise the path
    }

    #[test]
    fn verify_core_rejects_identity_public_key_even_with_a_validly_shaped_forgery() {
        // Forgery: for Y = identity, (R, z) = (z*G, z) trivially satisfies
        // z*G == R + c*0 for ANY z, with no secret knowledge at all. This
        // proves rejecting the identity explicitly is load-bearing, not
        // redundant with the equation check.
        let z = Fr::from(42u64);
        let r_point = SubgroupPoint::generator() * z;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_point.to_bytes());
        sig[32..].copy_from_slice(&z.to_bytes());

        let identity_bytes = SubgroupPoint::identity().to_bytes();
        assert!(!verify_core(&identity_bytes, b"forged", &sig));
        assert!(is_identity_pubkey_core(&identity_bytes));
    }

    #[test]
    fn identity_encodes_as_one_followed_by_31_zero_bytes() {
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(SubgroupPoint::identity().to_bytes(), expected);
    }

    #[test]
    fn exported_functions_round_trip_through_the_fixed_buffer() {
        let secret_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 9;
            b
        };
        unsafe {
            BUF[..32].copy_from_slice(&secret_bytes);
        }
        assert_eq!(derive_public_key(), 32);
        let pk_bytes = unsafe { BUF[..32].to_vec() };
        assert_eq!(pt(9).to_bytes().to_vec(), pk_bytes);

        unsafe {
            BUF[..32].copy_from_slice(&secret_bytes);
            BUF[32..64].copy_from_slice(&pk_bytes);
            BUF[64..68].copy_from_slice(b"test");
        }
        assert_eq!(test_sign(4), 64);
        let sig = unsafe { BUF[..64].to_vec() };

        unsafe {
            BUF[..32].copy_from_slice(&pk_bytes);
            BUF[32..96].copy_from_slice(&sig);
            BUF[96..100].copy_from_slice(b"test");
        }
        assert_eq!(verify(4), 1);

        unsafe {
            BUF[..32].copy_from_slice(&SubgroupPoint::identity().to_bytes());
        }
        assert_eq!(is_identity_pubkey(), 1);
    }
}
