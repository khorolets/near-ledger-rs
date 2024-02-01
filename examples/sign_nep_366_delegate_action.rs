use std::{convert::TryInto, str::FromStr};

use near_account_id::AccountId;
use near_crypto::{SecretKey, Signature};
use near_ledger::NEARLedgerError;
use near_primitives::action::delegate::{DelegateAction, SignedDelegateAction};
use slip10::BIP32Path;

use crate::common::display_pub_key;

#[path = "./common/lib.rs"]
mod common;

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();

    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
    let public_key = near_ledger::get_public_key_with_display_flag(hd_path.clone(), false)?;
    display_pub_key(public_key);

    let delegate_public_key =
        near_crypto::PublicKey::ED25519(near_crypto::ED25519PublicKey::from(public_key.to_bytes()));

    let sender_id = AccountId::from_str("bob.near").unwrap();

    let sk = SecretKey::from_seed(
        near_crypto::KeyType::SECP256K1,
        &format!("{:?}", public_key),
    );
    let public_key_secp = sk.public_key();

    let transfer = near_primitives::transaction::Action::Transfer(
        near_primitives::transaction::TransferAction {
            deposit: 150000000000000000000000, // 0.15 NEAR
        },
    );

    let stake = near_primitives::transaction::Action::Stake(Box::new(
        near_primitives::transaction::StakeAction {
            stake: 1157130000000000000000000, // 1.15713 NEAR,
            public_key: public_key_secp.clone(),
        },
    ));

    let add_key_fullaccess = near_primitives::transaction::Action::AddKey(Box::new(
        near_primitives::transaction::AddKeyAction {
            public_key: public_key_secp.clone(),
            access_key: near_primitives_core::account::AccessKey {
                nonce: 127127127127,
                permission: near_primitives_core::account::AccessKeyPermission::FullAccess,
            },
        },
    ));
    let actions = vec![transfer, stake, add_key_fullaccess]
        .into_iter()
        .map(|action| action.try_into().unwrap())
        .collect::<Vec<_>>();

    let delegate_action = DelegateAction {
        sender_id,
        receiver_id: AccountId::from_str("alice.near").unwrap(),
        actions,
        nonce: 127127122121,
        max_block_height: 100500,
        public_key: delegate_public_key,
    };

    let signature_bytes =
        near_ledger::sign_message_nep366_delegate_action(&delegate_action, hd_path)?;

    let signature = Signature::from_parts(near_crypto::KeyType::ED25519, &signature_bytes).unwrap();

    let signed_delegate = SignedDelegateAction {
        delegate_action,
        signature,
    };
    log::info!("{:#?}", signed_delegate);
    assert!(signed_delegate.verify());
    Ok(())
}
