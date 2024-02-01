use std::{convert::TryInto, str::FromStr};

use near_account_id::AccountId;
use near_crypto::{InMemorySigner, SecretKey};
use near_ledger::NEARLedgerError;
use near_primitives::{
    action::delegate::{DelegateAction, SignedDelegateAction},
    signable_message::{SignableMessage, SignableMessageType},
};
use near_primitives_core::hash::CryptoHash;

#[path = "../common/lib.rs"]
mod common;

fn tx(ledger_pub_key: ed25519_dalek::PublicKey) -> near_primitives::transaction::Transaction {
    let sender_id = AccountId::from_str("bob.near").unwrap();

    let transaction_public_key = near_crypto::PublicKey::ED25519(
        near_crypto::ED25519PublicKey::from(ledger_pub_key.to_bytes()),
    );
    let block_hash = "Cb3vKNiF3MUuVoqfjuEFCgSNPT79pbuVfXXd2RxDXc5E"
        .parse::<CryptoHash>()
        .unwrap();

    let signer_account_str = hex::encode(&ledger_pub_key.to_bytes());

    let mut tx = near_primitives::transaction::Transaction {
        public_key: transaction_public_key,
        block_hash,
        nonce: 103595482000005,
        signer_id: AccountId::from_str(&signer_account_str).unwrap(),
        receiver_id: sender_id.clone(),
        actions: vec![],
    };

    let sk = SecretKey::from_seed(
        near_crypto::KeyType::ED25519,
        &format!("{:?}", ledger_pub_key),
    );

    let signer = InMemorySigner::from_secret_key(sender_id.clone(), sk.clone());
    let delegate_public_key = sk.public_key();

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
        public_key: delegate_public_key,
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
