use std::{convert::TryInto, str::FromStr};

use near_account_id::AccountId;
use near_crypto::{InMemorySigner, SecretKey};
use near_ledger::NEARLedgerError;
use near_primitives::{
    action::delegate::{DelegateAction, SignedDelegateAction},
    signable_message::{SignableMessage, SignableMessageType},
};

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::PublicKey) -> near_primitives::transaction::Transaction {
    let mut tx = common::tx_template(ledger_pub_key);

    let sk = SecretKey::from_seed(
        near_crypto::KeyType::ED25519,
        &format!("{:?}", ledger_pub_key),
    );

    let sender_id = AccountId::from_str("bob.near").unwrap();
    let signer = InMemorySigner::from_secret_key(sender_id.clone(), sk.clone());
    let public_key = sk.public_key();

    const SIZE: usize = 3;
    let transfers = (0..SIZE)
        .map(|_el| {
            near_primitives::transaction::Action::Transfer(
                near_primitives::transaction::TransferAction {
                    deposit: 150000000000000000000000 * _el as u128, // 0.15 NEAR
                },
            )
        })
        .map(|action| action.try_into().unwrap())
        .collect::<Vec<_>>();

    let delegate_action = DelegateAction {
        sender_id,
        receiver_id: AccountId::from_str("alice.near").unwrap(),
        actions: transfers,
        nonce: 127127122121,
        max_block_height: 100500,
        public_key,
    };
    let signable_message =
        SignableMessage::new(&delegate_action, SignableMessageType::DelegateAction);
    let signature = signable_message.sign(&signer);

    let signed_delegate = SignedDelegateAction {
        delegate_action,
        signature,
    };
    assert!(signed_delegate.verify());

    tx.actions = vec![near_primitives::transaction::Action::Delegate(Box::new(
        signed_delegate,
    ))];
    tx
}

fn main() -> Result<(), NEARLedgerError> {
    common::get_key_sign_and_verify_flow(tx)
}
