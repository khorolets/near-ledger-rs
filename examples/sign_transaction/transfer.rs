use near_ledger::NEARLedgerError;

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::VerifyingKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);
    tx.actions = vec![near_primitives::transaction::Action::Transfer(
        near_primitives::transaction::TransferAction {
            deposit: 1234560000000000000000000000, // 1234.56 NEAR
        },
    )];
    near_primitives::transaction::Transaction::V0(tx)
}

fn main() -> Result<(), NEARLedgerError> {
    let result_signature_from_speculos_test = hex::decode("a8cc807ff4e83df0a5834af232550ccd15f09f829e0e73a88b6175e41d001085f2087d0b03fb36faf07d3b261d2d11a0e7b92a244c0dfd57e6daa3b91ae42205").unwrap();

    common::get_key_sign_and_verify_flow_with_cli_parse(tx, result_signature_from_speculos_test)
}
