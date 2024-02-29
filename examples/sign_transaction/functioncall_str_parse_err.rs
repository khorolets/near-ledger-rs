use near_ledger::NEARLedgerError;
use near_primitives::transaction::FunctionCallAction;

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::PublicKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key.clone());

    let mut bytes = vec![];
    bytes.push(123u8);

    bytes.extend((0..255).into_iter().collect::<Vec<_>>());

    let f_call = FunctionCallAction {
        method_name: "saturating_add_signed".to_string(),
        args: bytes,
        gas: 127127122121,
        deposit: 150000000000000000000000, // 0.15 NEAR,
    };

    tx.actions = vec![near_primitives::transaction::Action::FunctionCall(
        Box::new(f_call),
    )];
    tx
}

fn main() -> Result<(), NEARLedgerError> {
    common::get_key_sign_and_verify_flow(tx)?;
    Ok(())
}
