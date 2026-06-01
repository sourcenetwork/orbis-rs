# New DKG Flow

Status: working draft.

This document describes the intended fresh DKG flow against the rebuilt Orbis
bulletin. The current Rust node and the rebuilt Go bulletin are not expected to
work together yet; this is the target protocol shape we will implement toward.

## Phase 1: Node Declares Itself To The Chain

When an `orbis-node` starts, it declares the network information that other
participants need in order to include it in rings and run DKG with it.

The node registers a `NodeInfo` record on the bulletin:

```rust
pub struct NodeInfo {
    pub peer_id: String,
    pub controller_key: String,
    pub whitelisted_policy_ids: Vec<String>,
    pub whitelisted_ring_ids: Vec<String>,
}
```

### Fields

- `peer_id`: the node's P2P network identity. Other ring participants use this
  to connect to the node for DKG protocol messages.
- `controller_key`: an externally controlled key that is allowed to update this
  node's `NodeInfo`.
- `whitelisted_policy_ids`: policy IDs this node trusts to make DKG
  participation decisions for it.
- `whitelisted_ring_ids`: specific rings this node is willing to complete DKG
  for.

The allowlist has two ways to approve participation:

- Policy allowlist: if a ring's `policy_id` is in `whitelisted_policy_ids`, the
  node operator is saying, "I trust this policy to make DKG decisions for me."
  A policy could be controlled by a bank, a dapp multisig, or another external
  governance process.
- Ring allowlist: if a ring's ID is in `whitelisted_ring_ids`, the node will
  participate in that specific ring. This gives the operator more direct
  control when they do not want to trust the broader policy.

If either the ring's `policy_id` is in `whitelisted_policy_ids` or the ring ID
is in `whitelisted_ring_ids`, the node is willing to participate in DKG for
that ring.

### Ownership And Updates

The node does not keep the controller key internally. The controller key is
stored externally from the node and can create or update the `NodeInfo` record
on the fly.

This lets node operators change participation policy without having to access the node:

- update the advertised `peer_id`
- update the external `controller_key`
- add or remove policy allowlist entries
- add or remove specific ring ID allowlist entries

### Default Allowlist CLI

There is a CLI command that adds default policy_ids and ring IDs to the node's
allowlist.

For the target flow, this command should become the operator's first step after
or during node startup:

1. start the node
2. register or update `NodeInfo` on chain
3. add default allowlist entries for the rings/policies the node is willing to
   serve

## Phase 2: User Creates A Ring On The Bulletin

The start of a fresh DKG happens on the bulletin.

A user calls `CreateRing` with the ring information they want created:

- `policy_id`: the policy that governs whether the sender is allowed to create
  this ring.
- `threshold`: the number of participating nodes required for the ring.
- participant node keys: the node key IDs of the nodes that should participate
  in the DKG.
- `pss_interval`: optional timing information for future proactive secret
  sharing refreshes.
- `nonce`: caller-provided uniqueness data for the ring ID.

The bulletin checks the `policy_id` and decides whether the transaction sender
is authorized to create the ring. If the sender is allowed, the bulletin stores
the ring as a pending DKG ring.

At this point, the ring exists on chain, but DKG has not completed yet. The ring
contains the intended participants and threshold, but the final ring public key
has not been produced by the nodes.

The ring starts in an unfinalized state. The chain derives the `ring_id` by
hashing the ring creation fields. The nonce is included so a user can create a
new ring with the same policy, participants, threshold, and PSS interval without
colliding with a previous ring ID. The ring public key is left blank until DKG
completes.

Other ring dependent operation can not happen until the ring is finalized (Store document, create dervation, updateRingbyAcp)

In a ring reshare the checks of whitelist happens on the bulletin and at the node level.

## Phase 3: Cascade Kickoff Through A Relayer Node

After the ring has been created on the bulletin, anyone can kick off the DKG.
This will most likely be the same user who created the ring, but it does not
have to be.

The caller sends a `start_dkg` request to a relayer node. A relayer node is any
`orbis-node` that can read the ring from the bulletin and propagate the DKG
startup message into the P2P network.

The relayer's job is not to decide the ring membership itself. The relayer uses
the ring that already exists on the bulletin as the source of truth:

- read the pending ring by `ring_id`
- read the participant `NodeInfo` records for the ring's node keys
- resolve those node keys into P2P `peer_id`s
- send the DKG startup message into the participant network

This creates a cascade: one external `start_dkg` call reaches one relayer node,
and that relayer fans the DKG start message out to the nodes that are listed on
the bulletin ring.

## Phase 4: Nodes Run Fresh DKG Off Chain

After the cascade reaches the ring participants, each node treats the bulletin
ring as the source of truth for the ceremony. Before participating, a node
checks that the ring is still pending, that its own node key is listed as a
participant, and that its local `NodeInfo` allowlist permits it to complete DKG
for that ring or policy.

Once those checks pass, the participants run the fresh DKG protocol over the
P2P network. At a high level, each node contributes its own randomness,
broadcasts a public commitment, privately sends shares to the other
participants, verifies the shares it receives, and then computes its final local
secret share. All honest participants should compute the same aggregate ring
public key, but no one has posted that result back to the bulletin yet.

At the end of this phase, each successful participant has locally stored:

- its final secret share for the ring
- the public polynomial data needed for later signing/verification
- the aggregate `ring_pk` computed from the DKG ceremony

## Phase 5: Nodes Finalize The Ring On The Bulletin

Once a node completes the off-chain DKG ceremony, it calls `FinalizeRing` on the
bulletin with the `ring_id` and the aggregate ring public key it computed
locally.

`FinalizeRing` records confirmations from participant nodes. Each confirmation
says, in effect: "this node completed DKG for this ring and computed this
`ring_pk`." The bulletin tracks participant confirmations and finalizes only
after all nodes listed in the ring have confirmed.

When every participant has confirmed, the bulletin finalizes the ring by setting
the ring public key. After that point, ring-dependent operations such as
document storage, key derivation creation, and ACP-governed ring updates can use
the ring.

Conflicting `ring_pk` cleanup is not part of the eager finalization path. If a
ring gets stuck because participants disagree or fail to complete, cleanup can
be handled later by a PSS-backed or other lazy cleanup process.

## Phase 6: Ring Is Live

Once the bulletin finalizes the ring, the fresh DKG flow is complete.

The ring now has a committed `ring_pk`, the participant nodes have their local
secret shares, and ring-dependent functions are open for use. This includes
operations such as storing secrets/documents, creating key derivations, and
starting later ring updates.


## Extra Policy_id information
```
name: orbis ring policy
resources:
- name: ring_policy
  permissions:
  - name: create_ring
    expr: ring_creator
  relations:
  - name: ring_creator
    types:
    - actor
- name: ring
  permissions:
  - name: update_ring
    expr: operator
  relations:
  - name: operator
    types:
    - actor
```

The chain assumes a policy id spec that adheres to this to govern rings

It also requires a policy to set its own policy_id as a document as a ring_policy


## New DKG Flow but I got AI to make it a dr seuss rhyme

Oh, the node says hello with a peer-id hat,
and a controller key for changing this and that.
It keeps a small list of the rings it will do,
and the policies trusted to choose a good crew.

Then a person says, "Ring!" with a nonce in the mix,
with a threshold of nodes and a policy fix.
The bulletin checks it and writes it with care,
but the public key spot is still empty and bare.

Then a `start_dkg` call goes tap-tap-tap-tap
to a relayer node with a peer-finding map.
It reads from the chain and it sends with a zing,
"Come gather, you nodes, for this not-finished ring!"

So the nodes do the dance that the nodes have to do,
with a share for old me and a share for old you.
They whisper their secrets, they shout what is public,
and compute one `ring_pk`, neat and republic.

Then each calls the chain with the key it has seen.
If one key is different, the whole thing goes clean.
But if all of them match, then the bulletin sings,
"This ring is now live! Go do ring-powered things!"
