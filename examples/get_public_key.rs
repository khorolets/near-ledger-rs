use std::str::FromStr;

use near_ledger::{get_public_key, NEARLedgerError};
use slip10::BIP32Path;

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();
    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();

    let public_key = get_public_key(hd_path)?;

    log::info!("{:?}", public_key);
    log::info!(
        "{}",
        near_crypto::PublicKey::ED25519(
            near_crypto::ED25519PublicKey::from(public_key.to_bytes(),)
        )
    );

    Ok(())
}
