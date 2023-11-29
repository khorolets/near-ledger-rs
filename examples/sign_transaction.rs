use std::str::FromStr;

use near_ledger::NEARLedgerError;

use slip10::BIP32Path;

#[path = "./common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::PublicKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);
    tx.actions = vec![near_primitives::transaction::Action::Transfer(
        near_primitives::transaction::TransferAction {
            deposit: 150000000000000000000000,
        },
    )];
    tx
}

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();
    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();

    let public_key = near_ledger::get_public_key(hd_path.clone())?;
    common::display_pub_key(public_key);

    let unsigned_transaction = tx(public_key);

    let bytes = common::serialize_and_display_tx(unsigned_transaction);
    let signature_bytes = near_ledger::sign_transaction(bytes.clone(), hd_path)?;

    common::display_and_verify_signature(bytes, signature_bytes, public_key);

    Ok(())
}
