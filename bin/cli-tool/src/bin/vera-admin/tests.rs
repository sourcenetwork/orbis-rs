use super::*;
use alloy_primitives::B256;
use vera_client::ClientError;

#[test]
fn submission_accepts_only_matching_id_or_exact_duplicate() {
    let id = B256::repeat_byte(7);
    assert!(accept_submission(Ok(id), id).is_ok());
    assert!(accept_submission(Ok(B256::repeat_byte(8)), id).is_err());
    assert!(accept_submission(
        Err(ClientError::Rpc {
            code: -32602,
            message: "invalid transaction: duplicate transaction".into(),
        }),
        id,
    )
    .is_ok());
    for (code, message) in [
        (-32000, "invalid transaction: duplicate transaction"),
        (-32602, "duplicate transaction"),
        (-32602, "invalid transaction: nonce too low"),
        (-32602, "invalid transaction: invalid signature"),
    ] {
        let failure = ClientError::Rpc {
            code,
            message: message.into(),
        };
        let expected = failure.to_string();
        assert_eq!(
            accept_submission(Err(failure), id).unwrap_err().to_string(),
            expected
        );
    }
    assert!(accept_submission(Err(ClientError::MissingResult), id).is_err());
}

fn parse(command: &[&str]) -> std::result::Result<Args, clap::Error> {
    Args::try_parse_from(
        ["vera-admin", "--vera-config", "vera.json"]
            .iter()
            .chain(command),
    )
}

#[test]
fn delegation_accepts_only_the_scopes_this_tool_prepares() {
    let delegate = |scope| {
        parse(&[
            "delegate",
            "--worker-did",
            "did:key:worker",
            "--scope",
            scope,
            "--expires-at",
            "60",
            "--key-file",
            "actor-key",
            "--output",
            "token",
        ])
    };
    for (name, expected) in [
        ("orbis:ring", vera_client::DelegationScope::ManageRings),
        (
            "orbis:object:store",
            vera_client::DelegationScope::StoreThresholdObject,
        ),
    ] {
        let Command::Delegate { scope, .. } = delegate(name).unwrap().command else {
            panic!("delegate parsed as another command")
        };
        assert_eq!(scope, expected);
    }
    for rejected in [
        "acp:policy",
        "vera:token:revoke",
        "StoreThresholdObject",
        "",
    ] {
        assert!(delegate(rejected).is_err(), "{rejected} was accepted");
    }
}

#[test]
fn derivation_commands_require_their_inputs() {
    assert!(matches!(
        parse(&[
            "prepare-derivation",
            "derivation.json",
            "--token-file",
            "token"
        ])
        .unwrap()
        .command,
        Command::PrepareDerivation { .. }
    ));
    assert!(parse(&["prepare-derivation", "derivation.json"]).is_err());
    assert!(parse(&["derivation-id"]).is_err());
    let Command::Derivation {
        derivation_id,
        minimum_revision,
    } = parse(&["derivation", "ab", "--minimum-revision", "9"])
        .unwrap()
        .command
    else {
        panic!("derivation parsed as another command")
    };
    assert_eq!((derivation_id.as_str(), minimum_revision), ("ab", 9));
}

fn key_derivation() -> KeyDerivation {
    KeyDerivation {
        ring_id: "11".repeat(32),
        derivation: "tenant/key".into(),
        policy_id: "22".repeat(32),
        resource: "document".into(),
        permission: "sign".into(),
    }
}

#[test]
fn derivation_request_returns_the_registered_identity() {
    let derivation = key_derivation();
    let (parsed, id) = derivation::request(&serde_json::to_vec(&derivation).unwrap()).unwrap();
    assert_eq!(parsed, derivation);
    assert_eq!(
        id,
        ThresholdObject::KeyDerivation(derivation.clone())
            .id()
            .unwrap()
    );
    let mut extra = serde_json::to_value(&derivation).unwrap();
    extra["creator"] = "did:key:other".into();
    assert!(derivation::request(&serde_json::to_vec(&extra).unwrap()).is_err());
    let mut malformed = derivation;
    malformed.ring_id = "not a ring".into();
    assert!(derivation::request(&serde_json::to_vec(&malformed).unwrap()).is_err());
}

#[test]
fn derived_public_key_follows_only_an_active_ring() {
    use crypto::CryptoSerialize;
    use vera_client::rings::{RingPublicKeys, RingState};
    let (_, ring_key) = crypto::helpers::generate_keypair().unwrap();
    let keys = RingPublicKeys {
        public_key: hex::encode(ring_key.to_bytes().unwrap()),
        pet_public_key: None,
    };
    let derivation = key_derivation();
    let pending = RingState::Pending {
        keys: Some(keys.clone()),
        confirmations: Vec::new(),
    };
    assert_eq!(
        derivation::derived_public_key(&pending, &derivation).unwrap(),
        None
    );
    let active = RingState::Active { keys: keys.clone() };
    let derived = derivation::derived_public_key(&active, &derivation)
        .unwrap()
        .unwrap();
    assert_ne!(derived, keys.public_key);
    let mut other = derivation.clone();
    other.permission = "read".into();
    assert_ne!(
        derivation::derived_public_key(&active, &other)
            .unwrap()
            .unwrap(),
        derived
    );
    let corrupt = RingState::Active {
        keys: RingPublicKeys {
            public_key: "00".repeat(8),
            pet_public_key: None,
        },
    };
    assert!(derivation::derived_public_key(&corrupt, &derivation).is_err());
}
