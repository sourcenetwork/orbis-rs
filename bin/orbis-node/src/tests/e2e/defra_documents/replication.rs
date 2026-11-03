use super::*;
use defra_blockstore::{Blockstore, DefraBlockstore};
use defra_core::merge::{MergeBlock, MergeHandler, MergeOutcome};
use defra_db::merge::merge_handler::DbMergeHandler;
use std::collections::HashSet;

impl Documents {
    pub async fn verify_contents(&self) {
        let docs = defra_db::LensedAutoCommitFetcher::new(self.db.clone())
            .get_all("Signed")
            .await
            .unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(
            docs[0].get("name"),
            Some(&defra_document::NormalValue::String("signed".into()))
        );
    }

    pub async fn replicate_to(&self, target: &Self, created: &CreateResult) {
        let source_txn = self.db.new_txn(true).await.unwrap();
        let source = source_txn.blockstore().unwrap();
        let incoming = Arc::new(DefraBlockstore::new(target.db.store().clone(), false));
        let root = created.commit_cid.unwrap();
        let mut pending = vec![root];
        let mut visited = HashSet::new();
        while let Some(cid) = pending.pop() {
            if !visited.insert(cid) {
                continue;
            }
            let bytes = source.get(&cid.to_bytes()).await.unwrap().unwrap();
            assert_eq!(
                defra_core::block::generate_cid_from_bytes(&bytes).unwrap(),
                cid
            );
            if let Ok(block) = Block::from_dag_cbor(&bytes) {
                pending.extend(block.all_links());
                pending.extend(block.signature);
            }
            incoming.put(&cid, &bytes).await.unwrap();
        }
        let root_bytes = incoming.get(&root).await.unwrap().unwrap();
        let original = Block::from_dag_cbor(&root_bytes).unwrap();
        let signature_bytes = incoming
            .get(&original.signature.unwrap())
            .await
            .unwrap()
            .unwrap();
        let mut signature = Signature::from_dag_cbor(&signature_bytes).unwrap();
        signature.value[0] ^= 1;
        let forged_signature_bytes = signature.to_dag_cbor().unwrap();
        let forged_signature_cid = signature.generate_cid().unwrap();
        incoming
            .put(&forged_signature_cid, &forged_signature_bytes)
            .await
            .unwrap();
        let mut forged = original.clone();
        forged.signature = Some(forged_signature_cid);
        let forged_cid = forged.generate_cid().unwrap();
        let request = |cid, bytes, doc_id| MergeBlock {
            cid,
            block_data: bytes,
            doc_id,
            collection_id: "signed".into(),
            creator: "untrusted transport metadata".into(),
            sender_peer: Some("source".into()),
            is_explicit_replicator: false,
            explicit_replay_authorization: None,
            verified_creator: None,
        };
        let handler = DbMergeHandler::new(target.db.clone(), incoming);
        let invalid = request(
            forged_cid,
            forged.to_dag_cbor().unwrap().into(),
            defra_document::DocID::new_v0(forged_cid).to_string(),
        );
        let mut results = handler.handle_block_batch(&[invalid]).await;
        let outcome = results.remove(0).unwrap();
        assert!(
            matches!(outcome, MergeOutcome::Rejected { ref reason }
            if reason.contains("signature verification")),
            "{outcome:?}"
        );
        assert_eq!(target.count().await, 0);
        let valid = request(root, root_bytes, created.doc_id.to_string());
        let mut results = handler.handle_block_batch(&[valid]).await;
        assert!(matches!(results.remove(0).unwrap(), MergeOutcome::Merged));
        target.verify_contents().await;
    }
}
