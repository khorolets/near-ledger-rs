use std::{convert::TryFrom, str::FromStr};

use base58::FromBase58;
use ed25519_dalek::{PublicKey, Signature, SignatureError, Verifier};
use near_ledger::{NEARLedgerError, OnlyBlindSigning};
use near_primitives::types::AccountId;

use near_primitives::borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use slip10::BIP32Path;

fn too_long_tx() -> near_primitives::transaction::Transaction {
    let ledger_pub_key_str = "7be181e38cf773f8432a1af401f83b39f1222bad5a167875abba1baa2de477c7";
    let receiver_pub_key_str = "dc7e34eecec3096a4a661e10932834f801149c49dba9b93322f6d9de18047f9c";
    let ledger_pub_key_bytes = hex::decode(ledger_pub_key_str).unwrap();

    let ledger_pub_key = near_crypto::PublicKey::ED25519(
        near_crypto::ED25519PublicKey::try_from(ledger_pub_key_bytes.as_ref()).unwrap(),
    );

    let block_hash_str = "Cb3vKNiF3MUuVoqfjuEFCgSNPT79pbuVfXXd2RxDXc5E";

    let block_hash_bytes = block_hash_str.from_base58().unwrap();
    let mut block_hash: [u8; 32] = [0; 32];
    block_hash.copy_from_slice(&block_hash_bytes[0..32]);
    let block_hash = near_primitives::hash::CryptoHash(block_hash);

    const SIZE: usize = 27;

    let transfers = (0..SIZE)
        .map(|_el| {
            near_primitives::transaction::Action::Transfer(
                near_primitives::transaction::TransferAction {
                    deposit: 150000000000000000000000 * _el as u128,
                },
            )
        })
        .collect::<Vec<_>>();
    near_primitives::transaction::Transaction {
        public_key: ledger_pub_key,
        block_hash,
        nonce: 103595482000005,
        signer_id: AccountId::from_str(ledger_pub_key_str).unwrap(),
        receiver_id: AccountId::from_str(receiver_pub_key_str).unwrap(),
        actions: transfers,
    }
}

fn compute_hash(bytes: &[u8]) -> OnlyBlindSigning {
    let mut hasher = Sha256::new();
    hasher.update(&bytes);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);

    OnlyBlindSigning(hash)
}

pub fn verify_near(
    bytes: &[u8],
    pub_key: &PublicKey,
    signature: &Signature,
) -> Result<(), SignatureError> {
    let mut hasher = Sha256::new();
    hasher.update(&bytes);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);

    pub_key.verify(&hash, &signature)
}
fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();
    let unsigned_transaction = too_long_tx();
    log::info!("{:#?}", unsigned_transaction);

    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
    let public_key = near_ledger::get_public_key(hd_path.clone())?;

    let bytes = unsigned_transaction
        .try_to_vec()
        .expect("Transaction is not expected to fail on serialization");
    log::info!("bytes len : {}", bytes.len());
    let err = near_ledger::sign_transaction(bytes.clone(), hd_path.clone()).unwrap_err();

    let hash = compute_hash(&bytes);
    log::info!("hash: {}", hex::encode(&hash.0));
    assert!(matches!(err, NEARLedgerError::BufferOverflow(err_hash) if err_hash == hash));

    let signature = near_ledger::blind_sign_transaction(hash, hd_path)?;
    let signature = Signature::from_bytes(&signature).unwrap();

    log::info!("signature: {}", hex::encode(&signature));
    let result = verify_near(&bytes, &public_key, &signature);
    log::info!("result : {:#?}", result);
    assert!(result.is_ok());
    Ok(())
}
