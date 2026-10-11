use defra_core::signing::{RemoteSigner, SigningAuthorization};
use std::sync::{Arc, RwLock};

pub struct Signer {
    client: RwLock<Arc<defra_orbis::OrbisClient>>,
    public_key: Vec<u8>,
    public_key_hex: String,
    signer_did: String,
}

impl Signer {
    pub fn new(client: defra_orbis::OrbisClient) -> Self {
        Self {
            public_key: client.public_key_bytes().to_vec(),
            public_key_hex: client.public_key_hex().to_owned(),
            signer_did: client.signer_did().to_owned(),
            client: RwLock::new(Arc::new(client)),
        }
    }

    pub fn reconnect(&self, client: defra_orbis::OrbisClient) {
        assert_eq!(client.public_key_bytes(), self.public_key);
        assert_eq!(client.public_key_hex(), self.public_key_hex);
        assert_eq!(client.signer_did(), self.signer_did);
        *self.client.write().unwrap() = Arc::new(client);
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    pub fn signer_did(&self) -> &str {
        &self.signer_did
    }
}

impl RemoteSigner for Signer {
    fn sign_sync(
        &self,
        data: &[u8],
        authorization: Option<&SigningAuthorization>,
    ) -> Result<Vec<u8>, String> {
        let client = Arc::clone(&self.client.read().unwrap());
        client.sign_sync(data, authorization)
    }
}
