use near_crypto::SecretKey;
use near_ledger::NEARLedgerError;

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::VerifyingKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);
    let sk = SecretKey::from_seed(
        near_crypto::KeyType::SECP256K1,
        &format!("{:?}", ledger_pub_key),
    );
    let public_key = sk.public_key();
    tx.actions = vec![near_primitives::transaction::Action::DeleteKey(Box::new(
        near_primitives::transaction::DeleteKeyAction { public_key },
    ))];
    near_primitives::transaction::Transaction::V0(tx)
}

fn main() -> Result<(), NEARLedgerError> {
    common::get_key_sign_and_verify_flow_with_cli_parse(tx)
}
