use near_ledger::NEARLedgerError;


#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::PublicKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);

    const SIZE: usize = 3;
    let transfers = (0..SIZE)
        .map(|_el| {
            near_primitives::transaction::Action::Transfer(
                near_primitives::transaction::TransferAction {
                    deposit: 150000000000000000000000 * _el as u128, // 0.15 NEAR
                },
            )
        })
        .collect::<Vec<_>>();
    tx.actions = transfers;
    tx
}

fn main() -> Result<(), NEARLedgerError> {
    common::get_key_sign_and_verify_flow(tx)
}
