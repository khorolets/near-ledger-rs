use std::str::FromStr;

use near_ledger::NEARLedgerError;

use near_primitives_core::hash::CryptoHash;
use slip10::BIP32Path;

#[path = "./common/lib.rs"]
mod common;

fn long_tx(ledger_pub_key: ed25519_dalek::PublicKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);

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
    tx.actions = transfers;
    tx
}

fn compute_and_display_hash(bytes: &[u8]) -> CryptoHash {
    log::info!("---");
    log::info!("SHA-256 hash:");
    let hash = CryptoHash::hash_bytes(&bytes);
    log::info!("{:<15} : {}", "hash (hex)", hex::encode(hash.as_ref()));
    log::info!("{:<15} : {}", "hash (base58)", hash);
    log::info!("---");
    hash
}

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();
    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
    let public_key = near_ledger::get_public_key(hd_path.clone())?;
    common::display_pub_key(public_key);

    let unsigned_transaction = long_tx(public_key);

    let bytes = common::serialize_and_display_tx(unsigned_transaction);
    let payload = compute_and_display_hash(&bytes);

    let signature_bytes = near_ledger::blind_sign_transaction(payload, hd_path)?;
    common::display_and_verify_signature(bytes, signature_bytes, public_key);

    Ok(())
}
