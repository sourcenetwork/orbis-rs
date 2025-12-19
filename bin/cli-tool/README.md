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
- `--peer-ids`: Peer IDs for P2P connections in format `peer_id@endpoint` (required, one or more)

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

Perform proxy re-encryption to encrypt a secret for a reader using a ring public key from DKG.

**Basic Usage:**
```bash
cli-tool pre \
  --endpoint http://localhost:50051 \
  --ring-pk <ring_public_key_from_dkg> \
  --secret "my-secret-data" \
  --reader-pk <reader_public_key> \
  --peer-ids abc123def456...@127.0.0.1:8080 def789ghi012...@127.0.0.1:8081
```

**Using Short Flags:**
```bash
cli-tool pre -e http://localhost:50051 \
  --ring-pk <ring_public_key_from_dkg> \
  --secret "my-secret-data" \
  --reader-pk <reader_public_key> \
  --peer-ids abc123def456...@127.0.0.1:8080 def789ghi012...@127.0.0.1:8081
```

**Parameters:**
- `--endpoint` / `-e`: gRPC endpoint of the node (default: `http://localhost:50051`)
- `--ring-pk`: Ring public key obtained from a completed DKG session (required)
- `--secret`: Secret data to encrypt (required)
- `--reader-pk`: Public key of the reader who should be able to decrypt (required)
- `--peer-ids`: Peer IDs of nodes to participate in PRE (required, one or more)

**Example Output:**
```
Starting PRE session:
  Endpoint: http://localhost:50051
  Ring PK: abc123def456ghi789...
  Reader PK: def789ghi012jkl345...
  Peer IDs: ["abc123def456...@127.0.0.1:8080", "def789ghi012...@127.0.0.1:8081"]

PRE Result:
============================================================
  Status: completed
  Message: PRE operation completed successfully
  Encrypted Secret: <encrypted_secret_data>
```

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
Iroh connection string (peer_id@endpoint): abc123def456...@127.0.0.1:8080
```

Use this full connection string (including the `@` and endpoint) as the `--peer-ids` value.

## Examples

### Three-Node DKG Session

Start a DKG session with 3 nodes (threshold 2):

```bash
# On node 1 (localhost:50051)
cli-tool dkg -t 2 \
  --peer-ids node2_peer_id@127.0.0.1:8081 node3_peer_id@127.0.0.1:8082
```

### Multi-Node PRE Operation

Perform PRE with 3 participating nodes:

```bash
cli-tool pre \
 --ring-pk <hex from DKG> \   
 --secret "Plaintext" \
  --reader-pk <hex from generate-reader-key> \
  --reader-sk <hex from generate-reader-key> \    
  --peer-ids node1@127.0.0.1:8080 node2@127.0.0.1:8081 node3@127.0.0.1:8082
```

### Using Different Endpoints

Connect to a node on a different host:

```bash
cli-tool dkg \
  --endpoint http://192.168.1.100:50051 \
  --threshold 2 \
  --peer-ids remote_peer_id@192.168.1.101:8080
```