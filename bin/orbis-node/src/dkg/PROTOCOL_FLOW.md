# DKG Protocol Flow from start_dkg

This document explains how the DKG protocol messages are triggered from the `start_dkg` gRPC endpoint.

## Overview

The DKG protocol runs in 4 phases:
1. **Phase 1**: Generate polynomial & broadcast commitments
2. **Phase 2**: Generate & send shares
3. **Phase 3**: Verify shares (automatic)
4. **Phase 4**: Compute final secret share

## Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: start_dkg gRPC Call (Alice initiates)              │
└─────────────────────────────────────────────────────────────┘

User → gRPC: StartDkgRequest
  ├─ session_id, threshold, total_participants
  └─ peer_ids: [Bob, Charlie]

start_dkg() in service.rs:
  1. Create DKG session via coordinator.create_session()
  2. Connect to peers (Bob & Charlie)
  3. Send SessionInit message to all peers
  4. Trigger Phase 1: coordinator.initiate_phase1_commitments()
  5. Return "started" response

┌─────────────────────────────────────────────────────────────┐
│ STEP 2: Phase 1 - Commitments                              │
└─────────────────────────────────────────────────────────────┘

For Alice (initiator):
  coordinator.initiate_phase1_commitments():
    1. Get session, call session.generate_polynomial()
    2. Serialize commitment
    3. Send DkgMessage::Commitment to Bob & Charlie
    4. Wait for commitments from Bob & Charlie

For Bob & Charlie (receivers):
  protocol_handler.handle() receives SessionInit:
    1. coordinator.handle_message() processes SessionInit
    2. Creates their DKG session
    3. They should also call initiate_phase1_commitments()
    4. Send their commitment to Alice (and each other)

When commitment received:
  coordinator.handle_message() processes Commitment:
    1. Deserialize commitment
    2. Call session.receive_commitment()
    3. Increment commitments_received counter
    4. Check if all commitments received
    5. If yes → trigger Phase 2

┌─────────────────────────────────────────────────────────────┐
│ STEP 3: Phase 2 - Shares                                    │
└─────────────────────────────────────────────────────────────┘

When all commitments received:
  coordinator.check_and_trigger_phase2():
    1. Check commitments_received >= (total_nodes - 1)
    2. If yes → call coordinator.initiate_phase2_shares()

coordinator.initiate_phase2_shares():
  1. Get session, call session.generate_shares()
  2. For each peer:
     - Serialize share
     - Send DkgMessage::Share to that peer
  3. Update phase to Phase2Shares

When share received:
  coordinator.handle_message() processes Share:
    1. Deserialize share value
    2. Create DistributedShare
    3. Call session.receive_share() (verifies automatically)
    4. Increment shares_received counter
    5. Check if all shares received
    6. If yes → trigger Phase 4

┌─────────────────────────────────────────────────────────────┐
│ STEP 4: Phase 4 - Final Computation                        │
└─────────────────────────────────────────────────────────────┘

When all shares received:
  coordinator.check_and_trigger_phase4():
    1. Check shares_received >= (total_nodes - 1)
    2. If yes → call coordinator.initiate_phase4_completion()

coordinator.initiate_phase4_completion():
  1. Get session
  2. Call session.compute_secret_share()
  3. Call session.compute_aggregate_public_key()
  4. Update phase to Phase4Complete
  5. DKG complete! ✅

## Message Flow Example (3 nodes: Alice, Bob, Charlie)

```
Time    Alice                    Bob                      Charlie
─────────────────────────────────────────────────────────────────
T0      start_dkg() called
        ├─ Create session
        ├─ Connect to Bob, Charlie
        ├─ Send SessionInit → Bob
        ├─ Send SessionInit → Charlie
        └─ initiate_phase1_commitments()
        
T1      Generate polynomial
        Send Commitment → Bob
        Send Commitment → Charlie
        
T2                          Receive SessionInit
                            Create session
                            initiate_phase1_commitments()
                            Generate polynomial
                            Send Commitment → Alice
                            Send Commitment → Charlie
                            
T3                                              Receive SessionInit
                                                Create session
                                                initiate_phase1_commitments()
                                                Generate polynomial
                                                Send Commitment → Alice
                                                Send Commitment → Bob
                                                
T4      Receive Commitment from Bob
        Receive Commitment from Charlie
        All commitments received!
        check_and_trigger_phase2()
        initiate_phase2_shares()
        
T5      Generate shares
        Send Share → Bob
        Send Share → Charlie
        
T6                          Receive Commitment from Alice
                            Receive Commitment from Charlie
                            All commitments received!
                            check_and_trigger_phase2()
                            initiate_phase2_shares()
                            Generate shares
                            Send Share → Alice
                            Send Share → Charlie
                            
T7                                              Receive Commitment from Alice
                                                Receive Commitment from Bob
                                                All commitments received!
                                                check_and_trigger_phase2()
                                                initiate_phase2_shares()
                                                Generate shares
                                                Send Share → Alice
                                                Send Share → Bob
                                                
T8      Receive Share from Bob
        Receive Share from Charlie
        All shares received!
        check_and_trigger_phase4()
        initiate_phase4_completion()
        compute_secret_share() ✅
        
T9                          Receive Share from Alice
                            Receive Share from Charlie
                            All shares received!
                            check_and_trigger_phase4()
                            initiate_phase4_completion()
                            compute_secret_share() ✅
                            
T10                                             Receive Share from Alice
                                                Receive Share from Bob
                                                All shares received!
                                                check_and_trigger_phase4()
                                                initiate_phase4_completion()
                                                compute_secret_share() ✅
```

## Key Methods

### In `service.rs` (start_dkg):
- `coordinator.create_session()` - Creates DKG session
- `coordinator.set_peer_ids()` - Stores peer IDs for later use
- `coordinator.send_message_to_peer()` - Sends SessionInit
- `coordinator.initiate_phase1_commitments()` - Starts Phase 1

### In `coordinator.rs`:
- `initiate_phase1_commitments()` - Generates polynomial, broadcasts commitment
- `check_and_trigger_phase2()` - Checks if Phase 1 complete, triggers Phase 2
- `initiate_phase2_shares()` - Generates shares, sends to peers
- `check_and_trigger_phase4()` - Checks if Phase 2 complete, triggers Phase 4
- `initiate_phase4_completion()` - Computes final secret share

### In `protocol_handler.rs`:
- `handle()` - Receives messages, routes to coordinator
- Coordinator processes message and may trigger next phase

## Current Implementation Status

✅ Phase tracking infrastructure
✅ Message types defined
✅ Connection management
✅ Phase 1 initiation from start_dkg
✅ Phase 2 initiation when commitments complete
✅ Phase 4 initiation when shares complete
⏳ Commitment deserialization (TODO)
⏳ Share deserialization (partially done)
⏳ Proper node_id mapping (currently simplified)
