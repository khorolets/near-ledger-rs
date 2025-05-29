use near_ledger::NEARLedgerError;

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::VerifyingKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);
    tx.actions = common::batch_of_all_types_of_actions(ledger_pub_key);
    near_primitives::transaction::Transaction::V0(tx)
}

fn main() -> Result<(), NEARLedgerError> {
    // TODO: add actual obtained signature from speculos test somewhere in https://github.com/LedgerHQ/app-near/tree/develop/tests
    // on a per-actual-need basis
    let result_signature_from_speculos_test = hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

    common::get_key_sign_and_verify_flow_with_cli_parse(tx, result_signature_from_speculos_test)
}
