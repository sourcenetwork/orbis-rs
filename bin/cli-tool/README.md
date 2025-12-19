# CLI Tool

A command-line tool for interacting with an orbis network node. This tool allows you to start DKG (Distributed Key Generation) sessions, perform PRE (Proxy Re-Encryption) operations, and query node information.

## Installation

Build the CLI tool from the repository root:

```bash
cargo build --release --bin cli-tool
```

The binary will be located at `target/release/cli-tool` (or `target/debug/cli-tool` for debug builds).

## Commands

### DKG - Start a Distributed Key Generation Session

Start a DKG session to generate a distributed key across multiple nodes.

**Basic Usage:**
```bash
cli-tool dkg \
  --endpoint http://localhost:50051 \
  --threshold 2 \
  --peer-ids abc123def456...@127.0.0.1:8080 def789ghi012...@127.0.0.1:8081
```

**With Custom Session ID:**
```bash
cli-tool dkg \
  --endpoint http://localhost:50051 \
  --threshold 2 \
  --session-id my-custom-session-123 \
  --peer-ids abc123def456...@127.0.0.1:8080 def789ghi012...@127.0.0.1:8081
```

**Using Short Flags:**
```bash
cli-tool dkg -e http://localhost:50051 -t 2 \
  --peer-ids abc123def456...@127.0.0.1:8080 def789ghi012...@127.0.0.1:8081
```

**Parameters:**
- `--endpoint` / `-e`: gRPC endpoint of the node (default: `http://localhost:50051`)
- `--threshold` / `-t`: Number of nodes required to reconstruct the key (required)
- `--session-id` / `-s`: Optional session ID (auto-generated UUID if not provided)
- `--peer-ids`: Peer IDs for P2P connections in format `peer_id@host:port` (required, one or more)

**Example Output:**
```
Starting DKG session:
  Endpoint: http://localhost:50051
  Session ID: 550e8400-e29b-41d4-a716-446655440000
  Threshold: 2/3
  Peer IDs: ["abc123def456...@127.0.0.1:8080", "def789ghi012...@127.0.0.1:8081"]

Connecting to http://localhost:50051...
DKG Result:
============================================================
  Session ID: 550e8400-e29b-41d4-a716-446655440000
  Status: started
  Message: DKG session started with threshold 2 and 3 participants
```

### PRE - Start a Proxy Re-Encryption Session

Perform proxy re-encryption to encrypt a secret for a reader using a ring public key from DKG. This command performs a complete workflow:
1. Encrypts the plaintext secret to the ring public key
2. Sends the encrypted secret to the PRE service for re-encryption
3. Decrypts the re-encrypted secret using the reader's secret key

**Basic Usage:**
```bash
cli-tool pre \
  --endpoint http://localhost:50051 \
  --ring-pk <ring_public_key_from_dkg> \
  --secret "my-secret-data" \
  --reader-pk <reader_public_key> \
  --reader-sk <reader_secret_key> \
  --peer-ids abc123def456...@127.0.0.1:8080 def789ghi012...@127.0.0.1:8081
```

**Using Short Flags:**
```bash
cli-tool pre -e http://localhost:50051 \
  --ring-pk <ring_public_key_from_dkg> \
  --secret "my-secret-data" \
  --reader-pk <reader_public_key> \
  --reader-sk <reader_secret_key> \
  --peer-ids abc123def456...@127.0.0.1:8080 def789ghi012...@127.0.0.1:8081
```

**Parameters:**
- `--endpoint` / `-e`: gRPC endpoint of the node (default: `http://localhost:50051`)
- `--ring-pk`: Ring public key obtained from a completed DKG session in hex format (required)
- `--secret`: Plaintext secret data to encrypt and re-encrypt (required)
- `--reader-pk`: Reader's public key in hex format (from `generate-reader-key`) (required)
- `--reader-sk`: Reader's secret key in hex format (from `generate-reader-key`) (required)
- `--peer-ids`: Peer IDs of nodes to participate in PRE (required, one or more)

**Example Output:**
```
Starting PRE session:
  Endpoint: http://localhost:50051
  Ring PK: abc123def456ghi789...
  Reader PK: def789ghi012jkl345...
  Peer IDs: ["abc123def456...@127.0.0.1:8080", "def789ghi012...@127.0.0.1:8081"]

Step 1: Encrypting secret to ring public key...
  Encrypted secret created

Step 2: Sending to PRE service for re-encryption...
PRE Result:
============================================================
  Status: completed
  Message: PRE operation completed successfully

Step 3: Decrypting with reader secret key...
  Decrypted Secret: my-secret-data
```

### EncryptSecret - Encrypt a Secret to Ring Public Key

Encrypt a plaintext secret to a ring public key (from DKG). This is useful for encrypting data that will later be used in PRE operations.

**Basic Usage:**
```bash
cli-tool encrypt-secret \
  --secret "my-secret-data" \
  --ring-pk <ring_public_key_from_dkg>
```

**Parameters:**
- `--secret`: Plaintext secret to encrypt (required)
- `--ring-pk`: Ring public key from DKG in hex format (required)

**Example Output:**
```
Encrypting secret to ring public key...
  Ring PK: abc123def456ghi789...

Encrypted Secret (JSON):
============================================================
{"enc_cmt":"...","enc_secret":"..."}
```

The output is a JSON-encoded encrypted secret that can be used with the PRE service.

### GenerateReaderKey - Generate Reader Keypair

Generate a reader keypair (public and secret keys) for PRE decryption. The reader's public key is used during PRE operations, and the secret key is used to decrypt the re-encrypted data.

**Usage:**
```bash
cli-tool generate-reader-key
```

**Example Output:**
```
Generated Reader Keypair:
============================================================
Reader Secret Key (--reader-sk):
a1b2c3d4e5f6...
Reader Public Key (--reader-pk):
f6e5d4c3b2a1...
```

**Note:** Save both keys securely. The public key (`--reader-pk`) is used in PRE operations, and the secret key (`--reader-sk`) is needed to decrypt the re-encrypted data.

### Info - Query Node Information

Query information about a node (not yet implemented on server).

**Usage:**
```bash
cli-tool info --endpoint http://localhost:50051
```

**Using Short Flag:**
```bash
cli-tool info -e http://localhost:50051
```

**Parameters:**
- `--endpoint` / `-e`: gRPC endpoint of the node (default: `http://localhost:50051`)

## Getting Peer IDs

To get the peer ID and endpoint for a node, check the startup logs when running `orbis-node`. You should see a log entry like:

```
Iroh connection string (peer_id@host:port): abc123def456...@127.0.0.1:8080
```

Use this full connection string (including the `@` and host:port) as the `--peer-ids` value.

## Examples

### Three-Node DKG Session

Start a DKG session with 3 nodes (threshold 2):

```bash
# On node 1 (localhost:50051)
cli-tool dkg -t 2 \
  --peer-ids node2_peer_id@127.0.0.1:8081 node3_peer_id@127.0.0.1:8082
```

### Complete PRE Workflow

1. First, generate a reader keypair:
```bash
cli-tool generate-reader-key
```

2. Then perform PRE with the generated keys:
```bash
cli-tool pre \
  --ring-pk <hex_from_dkg> \
  --secret "my-secret-data" \
  --reader-pk <hex_from_generate_reader_key> \
  --reader-sk <hex_from_generate_reader_key> \
  --peer-ids node1@127.0.0.1:8080 node2@127.0.0.1:8081 node3@127.0.0.1:8082
```

### Encrypt Secret Separately

If you want to encrypt a secret without immediately performing PRE:

```bash
cli-tool encrypt-secret \
  --secret "my-secret-data" \
  --ring-pk <hex_from_dkg>
```

This outputs a JSON-encoded encrypted secret that can be stored or used later.

### Using Different Endpoints

Connect to a node on a different host:

```bash
cli-tool dkg \
  --endpoint http://192.168.1.100:50051 \
  --threshold 2 \
  --peer-ids remote_peer_id@192.168.1.101:8080
```