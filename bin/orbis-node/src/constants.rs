//! Constants used throughout the orbis-node codebase
//!
//! This module centralizes all configuration constants to make them easier to
//! maintain and understand. Constants are organized by category.

use std::time::Duration;

// ============================================================================
// Authentication Constants
// ============================================================================

/// Maximum allowed lifetime for a JWT bearer token (seconds).
///
/// Tokens with `exp - iat` greater than this value are rejected, preventing
/// long-lived credentials from being issued and then leaked. Set to 24 hours.
pub const MAX_TOKEN_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Allowed clock skew for JWT time claim validation (seconds).
///
/// Tokens are signed by clients and validated independently by each node, so
/// real deployments must tolerate small wall-clock differences across hosts or
/// containers. This mirrors the previous jwt-simple default leeway of 16 minutes.
pub const JWT_CLOCK_SKEW_LEEWAY_SECS: u64 = 16 * 60;

/// Maximum allowed byte length for a bearer token string.
///
/// Large request payloads are bound via digest claims rather than embedded in full,
/// so legitimate JWTs are small (typically well under 1 KiB). This cap prevents
/// oversized tokens from reaching DID resolution and signature verification.
pub const MAX_JWT_BYTES: usize = 16 * 1024;

// ============================================================================
// Cryptographic Constants
// ============================================================================

/// Maximum number of coefficients allowed in a polynomial commitment
///
/// This sets an upper bound on the degree of polynomials used in DKG sessions.
/// A polynomial commitment consists of G1 points, one for each coefficient.
/// This limit prevents DoS attacks via extremely large commitments and ensures
/// reasonable memory usage. The value of 256 is a reasonable upper bound that
/// allows for very large threshold values while still being practical.
pub const MAX_COMMITMENT_COEFFICIENTS: usize = 256;

// ============================================================================
// DKG Session Management Constants
// ============================================================================

/// Maximum number of concurrent DKG sessions allowed per node
///
/// This limit prevents unbounded memory growth and resource exhaustion. Each
/// DKG session maintains state including polynomial commitments, shares, and
/// cryptographic material. The value of 100 allows for substantial concurrent
/// activity while maintaining reasonable resource usage.
pub const MAX_DKG_SESSIONS: usize = 100;

/// Maximum number of persisted rings this node will manage locally.
///
/// PSS scans the local `RingIndex` linearly on each scheduler tick, so this
/// bounds the steady-state work a node can accumulate through fresh DKG and
/// reshare receiver participation. Existing ring entries may still be updated.
pub const MAX_LOCAL_RINGS_PER_NODE: usize = 256;

/// Time-to-live for DKG sessions before they are eligible for cleanup
///
/// Sessions older than this duration are automatically cleaned up to prevent
/// memory leaks from abandoned sessions. This is set to 30 minutes, which
/// provides ample time for DKG protocols to complete while ensuring stale
/// sessions don't accumulate indefinitely.
pub const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

/// Interval between session expiration checks
///
/// The session expiration worker runs periodically to clean up abandoned
/// sessions. This interval determines how often it checks for expired sessions.
/// Set to 1 minute for reasonable responsiveness without excessive overhead.
pub const SESSION_EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Timeout for a single DKG phase before the session is considered stalled
///
/// If a DKG session remains in the same phase for longer than this duration
/// (including `Initializing`) it is removed by the expiration worker. This
/// catches cases where the initiator crashes before Phase 1 starts, or where
/// a peer never sends its commitment or share, without waiting the full
/// SESSION_TTL. Set to 2 minutes, which gives ample headroom over
/// PEER_RESPONSE_TIMEOUT (10s) even when all peers need to respond.
pub const DKG_PHASE_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeout for the durable Phase 4 completion step before cleanup considers the
/// session abandoned.
///
/// Reshare completion can include threshold-signature retries and bulletin
/// confirmation work, so this must exceed the normal phase timeout.
pub const DKG_PHASE4_COMPLETION_TIMEOUT: Duration = Duration::from_secs(240);

/// How often to re-check session existence when an early message arrives before
/// the session has been created (e.g. a peer's commitment races with our own
/// SessionInit bulletin validation).  Kept small so the ceremony proceeds as
/// soon as the session appears.
pub const DKG_SESSION_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Maximum grace period for a non-SessionInit message whose session has not
/// appeared locally yet.
///
/// PSS refresh/reshare sessions are deterministic, so several old-committee
/// nodes can legitimately begin the same session at almost the same time. In
/// Docker CI the receiver may spend more than a few seconds validating or
/// creating the corresponding SessionInit while commitments and shares are
/// already queued behind it. Keep this shorter than a phase timeout, but long
/// enough that valid early messages are not dropped before the session appears.
pub const DKG_UNKNOWN_SESSION_MESSAGE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================================
// PRE (Proxy Re-Encryption) Constants
// ============================================================================

/// Maximum number of pending PRE responses
///
/// PRE responses are collected asynchronously from multiple nodes. This limit
/// prevents unbounded growth of response storage. The value of 1000 allows for
/// many concurrent PRE operations while maintaining reasonable memory usage.
pub const MAX_PRE_RESPONSES: usize = 1000;

// ============================================================================
// Sign (Threshold BLS Signing) Constants
// ============================================================================

/// Maximum number of pending Sign responses
///
/// Sign responses are collected asynchronously from multiple nodes. This limit
/// prevents unbounded growth of response storage. The value of 1000 allows for
/// many concurrent signing operations while maintaining reasonable memory usage.
pub const MAX_SIGN_RESPONSES: usize = 1000;

/// Maximum number of pending FROST nonce states
///
/// Nonce states are held on responder nodes between FROST Round 1 (nonce generation)
/// and Round 2 (signing). This limit prevents unbounded memory growth.
pub const MAX_NONCE_STATES: usize = 1000;

/// Time-to-live for FROST nonce states before they are eligible for cleanup
///
/// Nonce states should be consumed within seconds (between Round 1 and Round 2).
/// If a nonce is not consumed within this duration, the signing process was likely
/// abandoned (e.g., initiator crashed after Round 1). Set to 2 minutes to match
/// DKG_PHASE_TIMEOUT.
pub const SIGN_NONCE_TTL: Duration = Duration::from_secs(120);

/// Time-to-live for sign response entries before they are eligible for cleanup
///
/// Sign response entries should complete within seconds. If an entry is not
/// cleaned up within this duration, the signing coordinator was likely abandoned.
/// Set to 2 minutes as defense-in-depth behind the normal outer-function cleanup.
pub const SIGN_RESPONSE_TTL: Duration = Duration::from_secs(120);

/// Interval between sign state expiration checks
///
/// The sign expiration worker runs periodically to clean up abandoned nonce states
/// and stale response entries. Set to 30 seconds since signing operations are
/// faster than DKG and stale entries should be detected promptly.
pub const SIGN_EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(30);

// ============================================================================
// Network Constants
// ============================================================================

/// Maximum idle time before a pooled QUIC connection is closed (milliseconds).
///
/// Without this, a dead connection (e.g. network partition, peer crash without
/// a clean CLOSE) keeps the pool slot occupied and causes `open_stream()` to
/// hang until Quinn exhausts its retransmission backoff. On timeout the
/// connection closes, `open_stream()` fails, and the pool reconnects.
pub const NETWORK_IDLE_TIMEOUT_MS: u32 = 30_000;

// ============================================================================
// Peer ID Validation Constants
// ============================================================================

/// Maximum allowed length for peer ID strings in bytes
///
/// Peer IDs are used to identify nodes in the network. This limit prevents
/// DoS attacks via oversized peer ID strings. The value of 256 bytes provides
/// ample space for peer IDs (which are typically hex-encoded Ed25519 public
/// keys plus optional socket addresses) while preventing abuse.
pub const MAX_PEER_ID_LENGTH: usize = 256;

/// Expected length for hex-encoded Ed25519 public key (node ID)
///
/// Ed25519 public keys are 32 bytes, which when hex-encoded become 64
/// characters. This is the standard format for node IDs in the iroh network.
/// This constant is used to validate that peer IDs contain properly formatted
/// node IDs.
pub const EXPECTED_HEX_NODE_ID_LENGTH: usize = 64;

// ============================================================================
// Password Configuration Constants
// ============================================================================

/// Default filename for the password file
///
/// The password file stores the encryption password used for encrypting
/// ring key shares in local storage. This file should have restricted
/// permissions (0600) and be located in a secure directory.
pub const PASSWORD_FILE_NAME: &str = ".orbis_password";

/// Environment variable name for the encryption password
///
/// The password file (see [`PASSWORD_FILE_NAME`]) takes precedence; this variable is only
/// consulted when no file is present.
///
/// # Security warning — process listing exposure
///
/// Environment variables are visible to any process running as the same user via
/// `/proc/<pid>/environ` (Linux) and to privileged users via `ps auxe` or
/// `strings /proc/<pid>/environ`. On some systems they are also logged by init
/// supervisors (systemd `EnvironmentFile` journals, Docker daemon logs, etc.).
///
/// **Prefer the password file** (`~/.orbis_password`, mode 0600) for production
/// deployments. Only use this variable in short-lived, ephemeral environments
/// (CI pipelines, one-shot containers) where the process listing exposure window
/// is acceptable and the host is trusted.
///
/// If you must use this variable, inject it via a secrets manager (e.g.
/// `secretsmanager`, Vault, Kubernetes `secretKeyRef`) rather than embedding it
/// in a shell script or Dockerfile ENV instruction.
pub const PASSWORD_ENV_VAR: &str = "ORBIS_PASSWORD";

// ============================================================================
// Secret Key (Peer Identity) Configuration Constants
// ============================================================================

/// Default filename for the secret key file
///
/// The secret key file stores the encrypted iroh secret key used for
/// deterministic peer identity. This file is encrypted using the same
/// password as ring key shares.
pub const SECRET_KEY_FILE_NAME: &str = ".orbis_secret_key";

/// Environment variable name for the secret key (hex-encoded)
///
/// If set, this variable provides the iroh peer-identity secret key as a 64-character
/// hex string. The value is persisted encrypted in local storage on first use so that
/// the variable does not need to be set on subsequent restarts.
///
/// # Security warning — process listing exposure
///
/// This variable carries **raw key material**. It is visible to any process running
/// as the same user via `/proc/<pid>/environ` (Linux) and to privileged users via
/// `ps auxe`. It may also appear in:
/// - systemd journal entries if `EnvironmentFile=` is used with journald capture
/// - Docker daemon logs and `docker inspect` output for containers started with `-e`
/// - Shell history if set inline (`ORBIS_SECRET_KEY=abc orbis-node ...`)
///
/// **Preferred alternatives in priority order:**
/// 1. Let the node generate and persist the key automatically (first-run default).
/// 2. Use the secret key file (`~/.orbis_secret_key`, mode 0600) — this is encrypted
///    at rest with the ring-share password and never appears in process listings.
/// 3. Inject via a secrets manager (Vault, AWS Secrets Manager, Kubernetes
///    `secretKeyRef`) that writes the value into the environment of the process
///    without exposing it on the command line or in logs.
///
/// After the key has been stored in local storage, unset this variable to reduce
/// the ongoing exposure window.
pub const SECRET_KEY_ENV_VAR: &str = "ORBIS_SECRET_KEY";

// ============================================================================
// Bulletin Configuration Constants
// ============================================================================

/// The minimum amount a node can have in chain balance to start the node
pub const MIN_NODE_BALANCE: u64 = 1_000_000u64;

// ============================================================================
// Network Timeout Constants
// ============================================================================

/// Timeout for waiting on peer responses during signing and PRE operations
///
/// When a node sends a request to a peer and waits for a response, this timeout
/// prevents indefinite blocking if the peer stalls or becomes unresponsive.
/// Set to 10 seconds, which provides reasonable time for cryptographic operations
/// while ensuring the signing flow doesn't hang indefinitely.
pub const PEER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall timeout for collecting re-encryption shares from all peers.
///
/// Covers connect + send + recv for all nodes concurrently. Exceeding this
/// timeout returns InsufficientShares rather than hanging indefinitely when
/// fewer than threshold nodes are reachable.
pub const PRE_COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Overall timeout for each signing round (nonce collection or sign collection).
///
/// Covers connect + send + recv for all nodes concurrently. Exceeding this
/// timeout returns InsufficientShares rather than hanging indefinitely when
/// fewer than threshold nodes are reachable.
pub const SIGN_COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================================
// PSS (Proactive Secret Sharing) Constants
// ============================================================================

/// Default interval between automatic PSS reshare ceremonies (1 hour).
/// Set reshare_interval_secs to 0 on node startup to disable.
pub const DEFAULT_RESHARE_INTERVAL_SECS: u64 = 60 * 60;

/// Grace window subtracted from pss_interval when checking if a refresh is due.
/// Accounts for tick jitter and late last_pss writes so refreshes fire close to
/// the intended interval rather than up to check_interval seconds late.
pub const PSS_GRACE_PERIOD_SECS: u64 = 10;

/// Maximum number of attempts to collect threshold signatures at the end of a reshare.
pub const RESHARE_SIGNATURE_MAX_ATTEMPTS: usize = 6;

/// Delay between reshare threshold signature collection retries.
pub const RESHARE_SIGNATURE_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Maximum number of attempts for the post-refresh diagnostic threshold signature.
pub const REFRESH_HEALTH_CHECK_MAX_ATTEMPTS: usize = 6;

/// Delay between post-refresh diagnostic threshold signature retries.
pub const REFRESH_HEALTH_CHECK_RETRY_DELAY: Duration = Duration::from_millis(500);

/// How often a non-node-1 reshare member polls the bulletin waiting for the
/// node-1 bulletin update to land before releasing its PSS claim.
pub const RESHARE_BULLETIN_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum time to wait for bulletin confirmation before releasing the PSS claim
/// unconditionally. Slightly exceeds RESHARE_SIGNATURE_MAX_ATTEMPTS ×
/// SIGN_COLLECTION_TIMEOUT (6 × 30 s = 180 s) to guarantee we outlast node 1.
pub const RESHARE_BULLETIN_CONFIRM_TIMEOUT: Duration = Duration::from_secs(200);

// ============================================================================
// Nonce Serialization Constants (FROST)
// ============================================================================

/// Maximum number of commitments in a single deserialized batch.
/// Matches MAX_COMMITMENT_COEFFICIENTS since the number of signers
/// can never exceed the polynomial degree bound.
pub const MAX_COMMITMENTS: usize = MAX_COMMITMENT_COEFFICIENTS;

/// Maximum byte size for a single serialized nonce commitment.
/// Two compressed group elements should never exceed this.
pub const MAX_COMMITMENT_SIZE: usize = 1024;

/// Minimum bytes per commitment item: 4 (node_id) + 4 (length) + 1 (min payload).
pub const MIN_ITEM_SIZE: usize = 9;

/// Maximum byte length for the message field in a sign request.
/// Prevents oversized messages from bloating JWTs and network messages sent to all ring members.
pub const MAX_SIGN_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MiB
