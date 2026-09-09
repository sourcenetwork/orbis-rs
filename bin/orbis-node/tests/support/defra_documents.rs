use defra_core::{
    block::{Block, Signature},
    signing::{self, SigningConfig, SigningKeyType},
};
use defra_query::{
    mutator::{CreateResult, DocMutator},
    runner::DocFetcher,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

pub struct Documents {
    db: Arc<defra_db::DB<defra_storage::RegolithStore>>,
    path: PathBuf,
    signer: SigningConfig,
}

struct SigningGuard {
    previous: Option<SigningConfig>,
    allowed: bool,
}
impl Drop for SigningGuard {
    fn drop(&mut self) {
        signing::set_signing_config(self.previous.take());
        defra_core::block::go_verifiable_policy::allow_non_go_verifiable_signing(self.allowed);
    }
}

impl Documents {
    pub async fn new(path: &Path, signer: Arc<defra_orbis::OrbisClient>) -> Self {
        let db =
            Arc::new(defra_db::DB::new(defra_storage::RegolithStore::open(path).unwrap()).unwrap());
        db.create_collection(defra_schema::CollectionVersion::new(
            "Signed",
            "signed-v1",
            "signed",
            vec![
                defra_schema::FieldDescription::new(
                    "1",
                    "_docID",
                    defra_schema::FieldKind::doc_id(),
                ),
                defra_schema::FieldDescription::new("2", "name", defra_schema::FieldKind::string()),
            ],
        ))
        .await
        .unwrap();
        let config = SigningConfig {
            key_type: SigningKeyType::Bls,
            private_key_bytes: Vec::new(),
            public_key_bytes: signer.public_key_bytes().to_vec(),
            public_key_hex: signer.public_key_hex().to_owned(),
            remote_signer: Some(signer),
            signing_authorization: None,
        };
        Self {
            db,
            path: path.to_owned(),
            signer: config,
        }
    }

    pub async fn create(&self, name: &str) -> Result<CreateResult, String> {
        let _guard = SigningGuard {
            previous: signing::get_signing_config(),
            allowed: defra_core::block::go_verifiable_policy::non_go_verifiable_signing_allowed(),
        };
        signing::set_signing_config(Some(self.signer.clone()));
        defra_core::block::go_verifiable_policy::allow_non_go_verifiable_signing(true);
        let mut document = defra_document::Document::new();
        document.set("name", defra_document::NormalValue::String(name.into()));
        defra_db::AutoCommitMutator::new(self.db.clone())
            .create("Signed", document)
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn count(&self) -> usize {
        defra_db::LensedAutoCommitFetcher::new(self.db.clone())
            .get_all("Signed")
            .await
            .unwrap()
            .len()
    }

    pub async fn verify(&self, created: &CreateResult, expected_did: &str) {
        let cid = created.commit_cid.unwrap();
        let txn = self.db.new_txn(true).await.unwrap();
        let store = txn.blockstore().unwrap();
        let bytes = store.get(&cid.to_bytes()).await.unwrap().unwrap();
        assert_eq!(
            defra_core::block::generate_cid_from_bytes(&bytes).unwrap(),
            cid
        );
        let block = Block::from_dag_cbor(&bytes).unwrap();
        let signature_cid = block.signature.expect("stored block must be signed");
        let signature_bytes = store.get(&signature_cid.to_bytes()).await.unwrap().unwrap();
        assert_eq!(
            defra_core::block::generate_cid_from_bytes(&signature_bytes).unwrap(),
            signature_cid
        );
        let signature = Signature::from_dag_cbor(&signature_bytes).unwrap();
        assert_eq!(
            defra_db::block::verify::verified_signature_signer_did(&block, &signature).unwrap(),
            expected_did
        );
    }

    pub async fn reopen(self) -> Self {
        drop(self.db);
        let db = Arc::new(
            defra_db::DB::open(defra_storage::RegolithStore::open(&self.path).unwrap())
                .await
                .unwrap(),
        );
        Self {
            db,
            path: self.path,
            signer: self.signer,
        }
    }
}
