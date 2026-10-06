use super::*;
use crypto::PubPolyImpl;

fn polynomial() -> PubPolyImpl {
    let (_, key) = crypto::helpers::generate_keypair().expect("checking key");
    PubPolyImpl {
        commits: vec![key, GroupAffine::default()],
    }
}

#[test]
fn canonical_polynomial_requires_exact_degree_nonidentity_key_and_bounded_encoding() {
    let polynomial = polynomial();
    let bytes = polynomial.to_bytes().unwrap();
    let key = hex::encode(polynomial.eval(0).to_bytes().unwrap());
    decode::<PubPolyImpl>(&bytes, 2, &key).expect("zero higher coefficients are valid");
    assert!(decode::<PubPolyImpl>(&bytes, 1, &key).is_err());
    for malformed in [
        vec![],
        u32::MAX.to_le_bytes().to_vec(),
        [bytes.as_slice(), &[0]].concat(),
        bytes[..bytes.len() - 1].to_vec(),
        vec![0; MAX_POLYNOMIAL_BYTES + 1],
    ] {
        assert!(decode::<PubPolyImpl>(&malformed, 2, &key).is_err());
    }
    let mut bad_point = bytes;
    bad_point[4..4 + crypto::GROUP_POINT_SIZE].fill(0xff);
    assert!(decode::<PubPolyImpl>(&bad_point, 2, &key).is_err());
    let identity = PubPolyImpl {
        commits: vec![GroupAffine::default(); 2],
    };
    let identity_key = hex::encode(GroupAffine::default().to_bytes().unwrap());
    assert!(decode::<PubPolyImpl>(&identity.to_bytes().unwrap(), 2, &identity_key).is_err());
}

#[test]
fn valid_old_threshold_is_retryable_but_malformed_generation_is_not() {
    let polynomial = polynomial();
    let bytes = polynomial.to_bytes().unwrap();
    let key = hex::encode(polynomial.eval(0).to_bytes().unwrap());
    let bundle = RingShareBundle {
        share_bytes: zeroize::Zeroizing::new(Vec::new()),
        public_polynomial: hex::encode(&bytes),
        last_pss: 0,
    };
    assert!(matches!(
        match_bundle::<PubPolyImpl>(&bundle, &bytes, 1, &key),
        Err(PetError::GenerationMismatch)
    ));
    assert!(matches!(
        match_bundle::<PubPolyImpl>(&bundle, &bytes, 0, &key),
        Err(PetError::InvalidInput(_))
    ));
    assert!(matches!(
        match_bundle::<PubPolyImpl>(&bundle, &u32::MAX.to_le_bytes(), 1, &key),
        Err(PetError::InvalidInput(_))
    ));
    let mut corrupt = bundle;
    corrupt.public_polynomial = "ffffffff".into();
    assert!(matches!(
        match_bundle::<PubPolyImpl>(&corrupt, &bytes, 2, &key),
        Err(PetError::Storage(_))
    ));
}
