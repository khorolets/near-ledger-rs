use std::str::FromStr;

use ed25519_dalek::{Signature, Verifier};
use near_ledger::{NEARLedgerError, OnlyBlindSigning};
use near_primitives::types::AccountId;

use near_primitives::borsh::BorshSerialize;
use near_primitives_core::hash::CryptoHash;
use slip10::BIP32Path;

fn long_tx(ledger_pub_key: ed25519_dalek::PublicKey) -> near_primitives::transaction::Transaction {
    let public_key = near_crypto::PublicKey::ED25519(near_crypto::ED25519PublicKey::from(
        ledger_pub_key.to_bytes(),
    ));

    let block_hash = "Cb3vKNiF3MUuVoqfjuEFCgSNPT79pbuVfXXd2RxDXc5E"
        .parse::<CryptoHash>()
        .unwrap();

    let signer_account_str = hex::encode(&ledger_pub_key.to_bytes());
    let receiver_account_str = "dc7e34eecec3096a4a661e10932834f801149c49dba9b93322f6d9de18047f9c";

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
        public_key,
        block_hash,
        nonce: 103595482000005,
        signer_id: AccountId::from_str(&signer_account_str).unwrap(),
        receiver_id: AccountId::from_str(receiver_account_str).unwrap(),
        actions: transfers,
    }
}

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();
    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
    let public_key = near_ledger::get_public_key(hd_path.clone())?;

    let unsigned_transaction = long_tx(public_key);
    log::info!("{:#?}", unsigned_transaction);

    let bytes = unsigned_transaction
        .try_to_vec()
        .expect("Transaction is not expected to fail on serialization");
    log::info!("bytes len : {}", bytes.len());
    let err = near_ledger::sign_transaction(bytes.clone(), hd_path.clone()).unwrap_err();

    let payload = OnlyBlindSigning {
        byte_array: CryptoHash::hash_bytes(&bytes),
    };
    log::info!(
        "{:<25} : {}",
        "hash (hex)",
        hex::encode(payload.byte_array.as_ref())
    );
    log::info!("{:<25} : {}", "hash", payload.byte_array);
    assert!(matches!(err, NEARLedgerError::BufferOverflow(err_hash) if err_hash == payload));

    let signature_bytes = near_ledger::blind_sign_transaction(payload, hd_path)?;
    let signature = Signature::from_bytes(&signature_bytes).unwrap();

    let signature_near =
        near_crypto::Signature::from_parts(near_crypto::KeyType::ED25519, &signature_bytes)
            .expect("Signature is not expected to fail on deserialization");
    log::info!("{:<25} : {}", "signature (hex)", signature);
    log::info!("{:<25} : {}", "signature", signature_near);

    assert!(public_key
        .verify(&CryptoHash::hash_bytes(&bytes).as_ref(), &signature)
        .is_ok());
    Ok(())
}
