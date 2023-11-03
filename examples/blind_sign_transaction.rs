use std::{convert::TryFrom, str::FromStr};

use base58::FromBase58;
use near_ledger::NEARLedgerError;
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

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();
    let unsigned_transaction = too_long_tx();
    log::info!("{:#?}", unsigned_transaction);

    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();

    let bytes = unsigned_transaction
        .try_to_vec()
        .expect("Transaction is not expected to fail on serialization");
    log::info!("bytes len : {}", bytes.len());
    let err = near_ledger::sign_transaction(bytes.clone(), hd_path.clone()).unwrap_err();

    assert!(
        matches!(err, NEARLedgerError::APDUExchangeError(x) if x == "Ledger APDU retcode: 0x6990" )
    );

    let mut hasher = Sha256::new();
    hasher.update(&bytes);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);

    let signature = near_ledger::blind_sign_transaction(hash, hd_path)?;

    log::info!("signature: {}", hex::encode(&signature));
    Ok(())
}
