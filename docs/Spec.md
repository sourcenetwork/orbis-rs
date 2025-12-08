## Bulletin Board (global DB)
* This is where the encrypted secrets get stored
* secrets are small in nature (apikeys, secrets)
```rust
pub trait BulletinBoard {
    get()
    set()
}
```
* The idea here is to have a global DB that makes orbis nodes almost stateless (almost because they still need their keyshare)
* The default is source hub (need to create a module to handle this)
* Examples of BulletinBoards 
    * Centralized DB run by implementer
    * Local inside orbis node - this is possible but dangerous, there is currently no way for old ring nodes to share secrets with new ring nodes. So this can work only if ring nodes remain constant. Running this way is not on road map.
    * DefraDB? (explain drawback and why not default)

## Local DB
* persistent state that needs to be written to disk to be accessible on shutdown
* Can choose any kvdb as long as it fits spec 
```rust
pub trait LocalDb {
    get()
    set()
    delete()
    // these two functions explained below
    set_encrypted()
    get_encrypted()
}
```

* There is only really one item that if stored to disk needs to be encrypted which is the dkg key share. This can be handled by asking for a password upfront on spin up (or taking a file for devops automation) storing that password in memory and using it to encrypt and decrypt that item when needed. This saves having to implement LocalDb as an encrypted store and IMO leaves less footguns.

## Cache
* Just in case there is a lot stored in LocalDb and it is slow. Redis would make sense if the cache grows. I will write the interface here on the fly depending if it is needed. Also may not even need an interface as the cache can go into the LocalDb implementation (If you get something store it in cache when you get check cache first if not check db)

## Crypto
* Cryptography for orbis is build around proxy re-encryption. First A ring is selected then they preform a DKG. The public key for the ring is shared (somehow? probably with the bulletinboard) 

### DKG
* A DKG is a distrubted key generation
* It allows a ring of trust to create one keyshare with and each ring node to have In a M of N scheme 
```rust
pub trait DKGNode {
    pub fn new()
    /// Phase 1: Generate and broadcast polynomial commitment
    ///
    /// Each node generates a random polynomial of degree (threshold - 1)
    /// and creates commitments to its coefficients.
    pub fn generate_polynomial()
    /// Receive a polynomial commitment from another node
    pub fn receive_commitment()
    /// Phase 2: Generate shares for all other nodes
    ///
    /// Returns a vector of shares to be sent to each node
    pub fn generate_shares()
    /// Phase 3: Receive and verify a share from another node
    pub fn receive_shares()
    /// Phase 4: Compute the final secret share
    ///
    /// Once all shares are received and verified, compute the final share
    /// by summing all received shares (including own share)
    pub fn compute_secret_share()
    /// Compute the aggregate public key
    ///
    /// The aggregate public key is the sum of all nodes' constant terms
    /// in their polynomial commitments
    pub fn compute_aggregate_public_key()
    /// Get complaints about malicious nodes
    ///
    /// Returns a map of complainer_id -> list of accused node IDs
    pub fn get_complaints()
    /// Check if a node has been complained about by threshold of nodes
    ///
    /// Returns true if at least threshold nodes have complained about the given node
    pub fn is_node_excluded()
    /// Compute the public polynomial (sum of all commitments)
    ///
    /// This is used for verification in the re-encryption protocol
    pub fn compute_public_polynomial()
}
```

#### Visual Flow 
```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: SETUP                            │
└─────────────────────────────────────────────────────────────┘

Each node i:
  │
  │ Generate polynomial: fᵢ(x) = aᵢ₀ + aᵢ₁x + ... + aᵢₜ₋₁xᵗ⁻¹
  │
  │ Create commitment: Cᵢ = [aᵢ₀*G, aᵢ₁*G, ..., aᵢₜ₋₁*G]
  │
  ▼
Broadcast Cᵢ to all nodes
  │
  ├──► Node 1 receives: C₂, C₃, C₄, C₅
  ├──► Node 2 receives: C₁, C₃, C₄, C₅
  └──► ... (all nodes receive all commitments)


┌─────────────────────────────────────────────────────────────┐
│                    PHASE 2: SHARE GENERATION                │
└─────────────────────────────────────────────────────────────┘

Each node i:
  │
  │ For each node j (1 to n):
  │   shareᵢⱼ = fᵢ(j)
  │
  ▼
Send shares privately to recipients
  │
  ├──► Node 1 → Node 2: share₁₂
  ├──► Node 1 → Node 3: share₁₃
  ├──► Node 2 → Node 1: share₂₁
  └──► ... (all pairs)


┌─────────────────────────────────────────────────────────────┐
│                    PHASE 3: VERIFICATION                    │
└─────────────────────────────────────────────────────────────┘

Each node j receiving shareᵢⱼ:
  │
  │ Verify: Cᵢ.eval(j) == shareᵢⱼ * G
  │
  ├──► ✅ Valid: Store share
  └──► ❌ Invalid: Reject and complain


┌─────────────────────────────────────────────────────────────┐
│                    PHASE 4: FINAL SHARES                    │
└─────────────────────────────────────────────────────────────┘

Each node j:
  │
  │ final_shareⱼ = fⱼ(j) + Σᵢ≠ⱼ shareᵢⱼ
  │
  │ Compute aggregate PK = Σᵢ Cᵢ[0]
  │
  │ Compute public poly = Σᵢ Cᵢ
  │
  ▼
Output:
  - Final secret share (PriShare)
  - Aggregate public key (G1Affine)
  - Public polynomial (PubPoly)
```



### Key Reshare
* Not speced yet
* Simple concept similar to 

### Proxy ReEncyrption
* Allows a user to encrypt information to a ring of nodes. These nodes each hold a piece of a key and they can get together to do crypto nerd math to renecrypt it to a second public key of a second user
```rust
pub trait ThresholdDealer {
    /// for ring nodes

    pub fn new()
    /// Nodes Re-encrypt the secret Encrypter sent from their public key to Readers public key
    pub fn reencrypt()
   
    // For User Encrypter

    /// Encrypter encrypts a secret to store to the rings aggregate public key
    pub fn encrypt_secret()

    /// For User Reader

    /// Verifies a re-encryption reply from ring nodes
    pub fn verify()
    /// combines share using Lagrange interpolation
    pub fn recover()
    /// Reader decrypts a secret using own private key
    pub fn decrypt_secret()
}
```
* should allow for any key types 
#### Visual Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    ALICE ENCRYPTS                            │
└─────────────────────────────────────────────────────────────┘

Alice's Secret: "MySecret"
    │
    │ encrypt_secret(public_key_of_ring, secret)
    │
    ▼
Encrypted secret + Commitment (rG)
    │
    │ Send to nodes
    │
    ├───► Charlie (bulletins encrypted secret)
    └───► Dave   (bulletins encrypted secret)


┌─────────────────────────────────────────────────────────────┐
│                    BOB REQUESTS ACCESS                      │
└─────────────────────────────────────────────────────────────┘

Bob generates key pair (x, xG)
    │
    │ Request re-encryption
    │
    ├───► Charlie: "Re-encrypt for me! Here's xG"
    └───► Dave:   "Re-encrypt for me! Here's xG"


┌─────────────────────────────────────────────────────────────┐
│              CHARLIE & DAVE RE-ENCRYPT                      │
└─────────────────────────────────────────────────────────────┘

Charlie:
    │
    │ reencrypt(ski, xG, rG)
    │
    ▼
Re-encrypted Share + Proof
    │
    └───► Bob

Dave:
    │
    │ reencrypt(skj, xG, rG)
    │
    ▼
Re-encrypted Share + Proof
    │
    └───► Bob


┌─────────────────────────────────────────────────────────────┐
│                    BOB DECRYPTS                              │
└─────────────────────────────────────────────────────────────┘

Bob receives:
- Encrypted secret (from bulletin)
- Share from Charlie
- Share from Dave
    │
    │ verify() both proofs
    │ recover() combine shares
    │ decrypt_secret()
    │
    ▼
"MySecret" ✅
```

---

## User to Ring Communication 
* Rest? Through Libp2p? GRPC?
* How does the first flow work, do nodes make connections with ring first or wait for message from user then setup connection

## Authentication
TODO
* Authentication is meant to use acp from source hub. 
* unexplored open to input


## Networking
* TODO: look into iroh at first, maybe make it a triat and be generalizable as long as it is a channel