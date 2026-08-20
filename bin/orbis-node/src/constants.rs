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
/// containers. Keep the leeway small to avoid unnecessarily extending replay
/// windows after token expiry.
pub const JWT_CLOCK_SKEW_LEEWAY_SECS: u64 = 5 * 60;

/// Maximum tolerated drift (seconds) when attributing a relayer for forwarding an ACP-failing
/// Sign/PRE request (`unauthorized_request` report). The acceptor requires the relayer's
/// `signed_at` to be within this of `now` (the relay must be fresh so its signed `checked_at_height`
/// anchor is recent), and the report validation requires the relayer's `signed_at` to be within this
/// of the caller's JWT `iat` (the relayer must have forwarded promptly after the caller signed).
pub const RELAY_CHECK_MAX_DRIFT_SECS: u64 = 30;

/// Maximum allowed byte length for a bearer token string.
///
/// Large request payloads are bound via digest claims rather than embedded in full,
/// so legitimate JWTs are small (typically well under 1 KiB). This cap prevents
/// oversized tokens from reaching DID resolution and signature verification.
pub const MAX_JWT_BYTES: usize = 16 * 1024;

/// Maximum protobuf-encoded byte length for small public gRPC requests.
///
/// Small/control endpoints should never need a body larger than a JWT-sized
/// envelope. Larger data-carrying endpoints define their own request caps.
pub const MAX_SMALL_GRPC_REQUEST_BYTES: usize = MAX_JWT_BYTES;

// ============================================================================
// StoreSecret Constants
// ============================================================================

/// Maximum protobuf-encoded byte length for a StoreSecret request.
///
/// This caps the whole request rather than each field individually, keeping the
/// relay bound simple while preventing oversized encrypted documents, proofs,
/// and metadata from reaching hashing, parsing, or bulletin posting work.
pub const MAX_STORE_SECRET_REQUEST_BYTES: usize = 256 * 1024;

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

/// Maximum supported members in either side of a DKG committee.
///
/// This bounds ceremony state, pairwise networking, and the number of pages
/// required to repair a public phase. Reshare may have up to this many members
/// in each of its current and next committees.
pub const MAX_DKG_COMMITTEE_SIZE: usize = 50;

/// Maximum number of concurrent DKG sessions allowed per node
///
/// This limit prevents unbounded memory growth and resource exhaustion. Each
/// DKG session maintains state including polynomial commitments, shares, and
/// cryptographic material. The value of 100 allows for substantial concurrent
/// activity while maintaining reasonable resource usage.
pub const MAX_DKG_SESSIONS: usize = 100;

/// Maximum number of cached point-to-point QUIC connections across protocols.
///
/// Large rings can otherwise leave one connection per peer and protocol resident
/// indefinitely. The LRU pool reconnects transparently after eviction.
pub const MAX_CACHED_PEER_CONNECTIONS: usize = 256;

/// Maximum number of persisted rings this node will manage locally.
///
/// PSS scans the local `RingIndex` linearly on each scheduler tick, so this
/// bounds the steady-state work a node can accumulate through fresh DKG and
/// reshare receiver participation. Existing ring entries may still be updated.
pub const MAX_LOCAL_RINGS_PER_NODE: usize = 256;

/// Interval between session expiration checks
///
/// The session expiration worker runs periodically to clean up abandoned
/// sessions. This interval determines how often it checks for expired sessions.
/// Set to 1 minute for reasonable responsiveness without excessive overhead.
pub const SESSION_EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Hard deadline for one DKG attempt. Missing-message repair continues until
/// this deadline, unless the attempt explicitly completes or aborts first.
///
/// Shortened under `cfg(test)` so stall-detection tests can reach this
/// deadline without a real 15-minute wait, while staying comfortably above
/// `DKG_PREPARATION_TIMEOUT` so the existing attempt/preparation deadline
/// ordering still holds. `DKG_FINALIZE_WAIT_TIMEOUT` below is a separate,
/// still-generous bound for tests polling a *successful* ceremony to finish —
/// it does not shrink under test, since that wait has nothing to do with the
/// stall path this constant governs.
#[cfg(not(test))]
pub const DKG_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
#[cfg(test)]
pub const DKG_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// Generous bound for integration tests polling for a successful DKG/refresh/
/// reshare finalization. Deliberately decoupled from `DKG_ATTEMPT_TIMEOUT` so
/// shortening the stall-detection deadline under test doesn't tighten this
/// unrelated wait.
#[cfg(all(test, feature = "integration-test"))]
pub const DKG_FINALIZE_WAIT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Deadline for prepare/join/topology-probe coordination.
///
/// Shortened under `cfg(test)`, same rationale as `DKG_ATTEMPT_TIMEOUT` above: a test driving a
/// genuinely-unreachable-peer barrier failure (e.g. a refused connection, retried with backoff
/// until this deadline) would otherwise take up to the full production value in real time.
/// Existing tests that wait for this deadline already use a generous outer bound rather than
/// asserting its exact value, so shortening it only makes them complete faster.
#[cfg(not(test))]
pub const DKG_PREPARATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
#[cfg(test)]
pub const DKG_PREPARATION_TIMEOUT: Duration = Duration::from_secs(20);

/// Interval between retransmissions of the exact preparation topology probe.
pub const DKG_TOPOLOGY_PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// A Gossip topic is considered isolated only after it has remained without a
/// neighbor for this long. Individual neighbor changes are normal mesh churn.
pub const DKG_GOSSIP_ISOLATION_GRACE: Duration = Duration::from_secs(3);

/// Maximum retry backoff for preparation control messages and acknowledgements.
pub const DKG_PREPARATION_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(2);

/// A forwarded StartFresh request waits slightly longer than the leader's
/// preparation deadline so the leader's specific failure can reach the caller.
pub const DKG_FORWARDED_START_RESPONSE_GRACE: Duration = Duration::from_secs(30);

/// Lack of progress that triggers explicit public/private repair.
///
/// Shortened under `cfg(test)`, same rationale as `DKG_ATTEMPT_TIMEOUT` above: a live
/// fault-injection test that blocks a peer mid-ceremony needs repair to actually retry
/// against it within the test's real-time budget, not once per real 10 seconds.
#[cfg(not(test))]
pub const DKG_REPAIR_STALL_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(test)]
pub const DKG_REPAIR_STALL_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum backoff between repair attempts.
pub const DKG_MAX_REPAIR_BACKOFF: Duration = Duration::from_secs(30);

/// Maximum simultaneous private pair exchanges per node.
pub const DKG_PRIVATE_EXCHANGE_CONCURRENCY: usize = 4;

/// Maximum time a completed DKG session may remain in memory.
///
/// Normal Fresh/Refresh cleanup is immediate. Reshare cleanup may wait up to
/// `RESHARE_BULLETIN_CONFIRM_TIMEOUT` (200 seconds) for bulletin confirmation,
/// so five minutes leaves margin for that task while bounding leaks if explicit
/// cleanup never runs.
pub const DKG_COMPLETED_SESSION_TTL: Duration = Duration::from_secs(300);

/// Cadence of the Fresh-DKG soft-stall scan. Matches `DKG_REPAIR_STALL_INTERVAL`
/// so soft-stall detection is checked at least as often as repair itself runs.
///
/// Shortened under `cfg(test)` alongside `DKG_REPAIR_STALL_INTERVAL` and
/// `DKG_SOFT_STALL_NO_PROGRESS_THRESHOLD` so a live fault-injection soft-stall test
/// completes in real seconds rather than real minutes.
#[cfg(not(test))]
pub const DKG_SOFT_STALL_CHECK_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(test)]
pub const DKG_SOFT_STALL_CHECK_INTERVAL: Duration = Duration::from_millis(500);

/// How long a peer must have been failing repair/private-exchange retries
/// before the leader treats a Fresh DKG crypto phase as genuinely stalled and
/// aborts early rather than waiting for `DKG_ATTEMPT_TIMEOUT`. Public-plane
/// repair backs off to `DKG_MAX_REPAIR_BACKOFF` (30s) after a failed attempt,
/// so this comfortably spans at least two failed repair cycles (10s initial +
/// 30s + margin) before concluding the peer, not transient Gossip loss, is
/// the problem.
///
/// Shortened under `cfg(test)`, same rationale as `DKG_ATTEMPT_TIMEOUT`/
/// `DKG_REPAIR_STALL_INTERVAL` above; still comfortably spans several shortened
/// repair cycles (`DKG_REPAIR_STALL_INTERVAL` under test) before firing, so the
/// "real stall vs. transient loss" distinction the production value protects
/// still holds at test scale.
#[cfg(not(test))]
pub const DKG_SOFT_STALL_NO_PROGRESS_THRESHOLD: Duration = Duration::from_secs(60);
#[cfg(test)]
pub const DKG_SOFT_STALL_NO_PROGRESS_THRESHOLD: Duration = Duration::from_secs(3);

/// Minimum consecutive failed repair/retry attempts against one peer before
/// it counts toward soft-stall, in addition to the elapsed-time gate above.
/// Prevents a single missed repair cycle (or a scan racing a phase's very
/// first attempt) from being treated as a stall.
pub const DKG_SOFT_STALL_MIN_REPAIR_ATTEMPTS: u32 = 2;

/// TTL for a queryable Fresh DKG failure record after the attempt is torn
/// down. Long enough for a client polling `GetDkgSessionStatus` on a normal
/// interval to reliably observe the failure once before it ages out; short
/// enough not to accumulate unboundedly across many retried ceremonies.
pub const DKG_FAILED_SESSION_RECORD_TTL: Duration = Duration::from_secs(10 * 60);

// ============================================================================
// Ring Finalization Constants
// ============================================================================

/// Maximum retries for both halves of `post_and_verify_fresh_ring_finalization`:
/// reposting a `FinalizeRing` transaction whose confirmation is missing on-chain,
/// and retrying a failed `ring_finalization_status` query. Shared between the two
/// because both represent the same underlying condition (SourceHub is not yet
/// reflecting this node's confirmation) and should give up after comparable effort.
pub const FINALIZATION_PERSISTENCE_RETRY_LIMIT: usize = 8;

/// Initial backoff before retrying a failed `FinalizeRing` post/status query.
/// Also the value `retry_delay` resets to once this node's own confirmation
/// reappears mid-loop, since that clears the condition the backoff was for.
pub const FINALIZATION_PERSISTENCE_RETRY_INITIAL: Duration = Duration::from_millis(250);

/// Upper bound for the exponential backoff between finalization retries.
pub const FINALIZATION_PERSISTENCE_RETRY_CAP: Duration = Duration::from_secs(2);

/// Poll interval used while this node's own confirmation is already visible
/// on-chain but the full confirmation set is still being observed. Distinct
/// from the retry backoff above: this is a steady cadence, not exponential,
/// since there's no failure to back off from.
pub const FINALIZATION_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Hard deadline for the whole post-and-verify finalization loop. Bounds how
/// long a node will wait for every participant's `FinalizeRing` confirmation
/// to land on-chain before giving up on this ring.
pub const FINALIZATION_COMPLETION_TIMEOUT: Duration = Duration::from_secs(15 * 60);

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
/// abandoned (e.g., initiator crashed after Round 1 or did not select this signer).
/// This covers the 30-second Round 1 collection deadline plus 15 seconds of grace.
pub const SIGN_NONCE_TTL: Duration = Duration::from_secs(45);

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
/// QUIC idle timeout. DKG control and repair traffic can legitimately pause while
/// large commitments are computed, so keep the underlying connection longer than
/// an individual phase stall interval.
pub const NETWORK_IDLE_TIMEOUT_MS: u32 = 5 * 60 * 1_000;

/// QUIC keep-alive interval for active peer connections.
pub const NETWORK_KEEP_ALIVE_INTERVAL_MS: u64 = 10_000;

/// Maximum concurrently executing inbound P2P application work items.
///
/// Direct QUIC streams and authenticated Gossip frames share this node-wide
/// budget. Excess work is dropped before protocol deserialization.
pub const NETWORK_MAX_CONCURRENT_INGRESS_WORK: usize = 1024;

/// Maximum inbound P2P work items accepted from one immediate peer per second.
///
/// Direct streams and Gossip frames count against the same peer budget. DKG,
/// PRE, and Sign traffic should stay well below this in normal operation.
pub const NETWORK_MAX_INGRESS_EVENTS_PER_PEER_PER_SECOND: usize = 512;

/// Maximum in-flight gRPC requests per client connection.
pub const GRPC_CONCURRENCY_LIMIT_PER_CONNECTION: usize = 128;

/// Maximum concurrent HTTP/2 streams per gRPC client connection.
pub const GRPC_MAX_CONCURRENT_STREAMS: u32 = 256;

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

/// Environment variable naming the path of the password file
pub const PASSWORD_FILE_ENV_VAR: &str = "ORBIS_PASSWORD_FILE";

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

/// Maximum protobuf-encoded byte length for a Sign gRPC request.
///
/// Preserves the 1 MiB signed-message contract while leaving room for the
/// derivation id, optional fields, and request framing overhead.
pub const MAX_SIGN_REQUEST_BYTES: usize = MAX_SIGN_MESSAGE_BYTES + MAX_JWT_BYTES;
