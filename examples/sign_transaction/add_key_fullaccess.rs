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
    tx.actions = vec![near_primitives::transaction::Action::AddKey(Box::new(
        near_primitives::transaction::AddKeyAction {
            public_key,
            access_key: near_primitives_core::account::AccessKey {
                nonce: 127127127127,
                permission: near_primitives_core::account::AccessKeyPermission::FullAccess,
            },
        },
    ))];
    near_primitives::transaction::Transaction::V0(tx)
}

fn main() -> Result<(), NEARLedgerError> {
    // TODO: add actual obtained signature from speculos test somewhere in https://github.com/LedgerHQ/app-near/tree/develop/tests
    // on a per-actual-need basis
    let result_signature_from_speculos_test = hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

    common::get_key_sign_and_verify_flow_with_cli_parse(tx, result_signature_from_speculos_test)
}
