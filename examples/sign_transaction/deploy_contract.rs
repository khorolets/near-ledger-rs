use near_ledger::NEARLedgerError;
use near_primitives::transaction::DeployContractAction;
use near_primitives_core::hash::CryptoHash;

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::VerifyingKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);

    let code = core::iter::repeat(42u8).take(3000).collect::<Vec<_>>();

    let code_hash = CryptoHash::hash_bytes(&code);
    log::info!("Contract code hash: {:?}", code_hash);
    tx.actions = vec![near_primitives::transaction::Action::DeployContract(
        DeployContractAction { code },
    )];
    tx
}

fn main() -> Result<(), NEARLedgerError> {
    common::get_key_sign_and_verify_flow(tx)
}
