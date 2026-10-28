# Reshare participant selection

The public reshare topic is shared by the current and next committees. A
selection broadcast can therefore reach a departing dealer as well as the
members receiving new shares. Receiving that broadcast does not make the
dealer a member of the next committee.

The authenticated selection must originate from next-committee participant 1.
Every participant checks that the session is a main or PET reshare and that
the selection contains exactly the old threshold of distinct, in-range,
active current-committee dealers. Transport signature, origin and contribution
ledger checks remain in place.

| Local role | Additional validation | Local share effect |
| --- | --- | --- |
| Receiver or dealer/receiver | Each selected dealer's commitment and private share were independently accepted; the crypto implementation accepts the selection. | Apply the selection and advance the receiver's protocol. |
| Departing dealer | No receiver share check: this role never receives new shares. | Keep its share state unchanged; do not advance the receiver's protocol. |
| Standard participant | Invalid role for this reshare selection. | Reject. |

`preflight_reshare_participant_set` and `handle_reshare_participant_set` use
the same validation. The handler applies a selection only when validation
returns an instruction to advance a receiver. A valid broadcast to a departing
dealer is a successful no-op, rather than evidence of sender misconduct.
Malformed or unauthorized selections still fail validation on that dealer.

This public selection does not finalize membership or authorize deleting old
shares. Departing-dealer cleanup still requires the finalized ring record to
exclude the dealer. Receiver bundle promotion still waits for the finalized
committee and threshold to match the staged material.

The selection tests cover main and PET broadcasts to a departing dealer,
unchanged local share state, sender authentication, dealer bounds, inactive
dealers and duplicates at a valid threshold count. Existing receiver tests
reject selections without an independently accepted share. Native CI runs
this focused module for both BLS12-381 and Jubjub.
