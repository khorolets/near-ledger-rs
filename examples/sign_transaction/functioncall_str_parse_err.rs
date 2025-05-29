use near_ledger::NEARLedgerError;
use near_primitives::transaction::FunctionCallAction;

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::VerifyingKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);

    let mut bytes = vec![];
    bytes.push(123u8);

    bytes.extend((0..255).collect::<Vec<_>>());

    let f_call = FunctionCallAction {
        method_name: "saturating_add_signed".to_string(),
        args: bytes,
        gas: 127127122121,
        deposit: 150000000000000000000000, // 0.15 NEAR,
    };

    tx.actions = vec![near_primitives::transaction::Action::FunctionCall(
        Box::new(f_call),
    )];
    near_primitives::transaction::Transaction::V0(tx)
}

fn main() -> Result<(), NEARLedgerError> {
    // signature taken from https://github.com/LedgerHQ/app-near/blob/fc6c7e2cd0349cbfde938d9de2a92cfeb0d98a7d/tests/test_sign_transaction/test_function_call.py#L421
    let result_signature_from_speculos_test = hex::decode("936cb9a2b06160c6ff27aae978014285eeefb37e21461365306089833ef3e5a815947e11215302b3340f1b58486c47656eab453ecc47b29cc05fe277f268d90d").unwrap();

    common::get_key_sign_and_verify_flow_with_cli_parse(tx, result_signature_from_speculos_test)?;
    Ok(())
}
