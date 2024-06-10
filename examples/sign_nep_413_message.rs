use std::str::FromStr;

use ed25519_dalek::Signature;
use ed25519_dalek::Verifier;
use near_ledger::{NEARLedgerError, NEP413Payload};
use near_primitives::signable_message::{MessageDiscriminant, SignableMessage};
use near_primitives_core::{borsh, hash::CryptoHash};
use slip10::BIP32Path;

use crate::common::display_pub_key;

#[path = "./common/lib.rs"]
mod common;

pub fn display_and_verify_signature(
    msg: &NEP413Payload,
    signature_bytes: Vec<u8>,
    public_key: ed25519_dalek::PublicKey,
) {
    log::info!("---");
    log::info!("Signature:");
    let signature = Signature::from_bytes(&signature_bytes).unwrap();

    let msg_discriminant = MessageDiscriminant::new_off_chain(413).unwrap();
    let signable_message = SignableMessage {
        discriminant: msg_discriminant,
        msg,
    };

    let hash = CryptoHash::hash_bytes(&borsh::to_vec(&signable_message).unwrap());

    let signature_near =
        near_crypto::Signature::from_parts(near_crypto::KeyType::ED25519, &signature_bytes)
            .expect("Signature is not expected to fail on deserialization");
    log::info!("{:<20} : {}", "signature (hex)", signature);
    log::info!("{:<20} : {}", "signature (base58)", signature_near);

    assert!(public_key.verify(hash.as_ref(), &signature).is_ok());
    log::info!("---");
}

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();

    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
    let public_key = near_ledger::get_public_key_with_display_flag(hd_path.clone(), false)?;
    display_pub_key(public_key);

    let msg = NEP413Payload {
        messsage: "Makes it possible to authenticate users without having to add new access keys. This will improve UX, save money and will not increase the on-chain storage of the users' accounts./Makes it possible to authenticate users without having to add new access keys. This will improve UX, save money and will not increase the on-chain storage of the users' accounts./Makes it possible to authenticate users without having to add new access keys. This will improve UX, save money and will not increase the on-chain storage of the users' accounts.".to_string(),
        nonce: [42; 32],
        recipient: "alice.near".to_string(),
        callback_url: Some("myapp.com/callback".to_string()) 
    };

    let signature_bytes = near_ledger::sign_message_nep413(&msg, hd_path)?;

    display_and_verify_signature(&msg, signature_bytes, public_key);

    Ok(())
}
