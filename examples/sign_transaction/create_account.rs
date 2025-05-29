use near_ledger::NEARLedgerError;

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::VerifyingKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);
    tx.actions = vec![near_primitives::transaction::Action::CreateAccount(
        near_primitives::transaction::CreateAccountAction {},
    )];
    near_primitives::transaction::Transaction::V0(tx)
}

fn main() -> Result<(), NEARLedgerError> {
    common::get_key_sign_and_verify_flow_with_cli_parse(tx)
}
