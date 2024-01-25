#![allow(unused)]
use std::str::FromStr;

use ed25519_dalek::Signature;
use ed25519_dalek::Verifier;
use near_ledger::NEARLedgerError;
use near_primitives_core::{borsh, borsh::BorshSerialize, hash::CryptoHash, types::AccountId};
use slip10::BIP32Path;

pub fn display_pub_key(public_key: ed25519_dalek::PublicKey) {
    log::info!("---");
    log::info!("Public key:");
    log::info!("{:?}", public_key);
    log::info!("{:<10} : {}", "hex", hex::encode(public_key));
    log::info!(
        "{:<10} : {}",
        "base58",
        near_crypto::PublicKey::ED25519(
            near_crypto::ED25519PublicKey::from(public_key.to_bytes(),)
        )
    );
    log::info!("---");
}

pub fn tx_template(
    ledger_pub_key: ed25519_dalek::PublicKey,
) -> near_primitives::transaction::Transaction {
    let public_key = near_crypto::PublicKey::ED25519(near_crypto::ED25519PublicKey::from(
        ledger_pub_key.to_bytes(),
    ));
    let block_hash = "Cb3vKNiF3MUuVoqfjuEFCgSNPT79pbuVfXXd2RxDXc5E"
        .parse::<CryptoHash>()
        .unwrap();

    let signer_account_str = hex::encode(&ledger_pub_key.to_bytes());
    let receiver_account_str = "dc7e34eecec3096a4a661e10932834f801149c49dba9b93322f6d9de18047f9c";

    near_primitives::transaction::Transaction {
        public_key,
        block_hash,
        nonce: 103595482000005,
        signer_id: AccountId::from_str(&signer_account_str).unwrap(),
        receiver_id: AccountId::from_str(receiver_account_str).unwrap(),
        actions: vec![],
    }
}

pub fn serialize_and_display_tx(transaction: near_primitives::transaction::Transaction) -> Vec<u8> {
    log::info!("---");
    log::info!("Transaction:");
    log::info!("{:#?}", transaction);
    let bytes =
        borsh::to_vec(&transaction).expect("Transaction is not expected to fail on serialization");
    log::info!("transaction byte array length: {}", bytes.len());
    log::info!("---");
    bytes
}

pub fn display_and_verify_signature(
    msg: Vec<u8>,
    signature_bytes: Vec<u8>,
    public_key: ed25519_dalek::PublicKey,
) {
    log::info!("---");
    log::info!("Signature:");
    let signature = Signature::from_bytes(&signature_bytes).unwrap();

    let signature_near =
        near_crypto::Signature::from_parts(near_crypto::KeyType::ED25519, &signature_bytes)
            .expect("Signature is not expected to fail on deserialization");
    log::info!("{:<20} : {}", "signature (hex)", signature);
    log::info!("{:<20} : {}", "signature (base58)", signature_near);

    assert!(public_key
        .verify(&CryptoHash::hash_bytes(&msg).as_ref(), &signature)
        .is_ok());
    log::info!("---");
}

pub fn get_key_sign_and_verify_flow<F>(f_transaction: F) -> Result<(), NEARLedgerError>
where
    F: FnOnce(ed25519_dalek::PublicKey) -> near_primitives::transaction::Transaction,
{
    env_logger::builder().init();
    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();

    let public_key = near_ledger::get_public_key_with_display_flag(hd_path.clone(), false)?;
    display_pub_key(public_key);

    let unsigned_transaction = f_transaction(public_key);

    let bytes = serialize_and_display_tx(unsigned_transaction);
    let signature_bytes = near_ledger::sign_transaction(bytes.clone(), hd_path)?;

    display_and_verify_signature(bytes, signature_bytes, public_key);

    Ok(())
}
