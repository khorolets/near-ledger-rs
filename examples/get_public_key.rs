use std::str::FromStr;

use base58::ToBase58;
use near_ledger::{get_public_key, NEARLedgerError};
use slip10::BIP32Path;

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();
    let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();

    let public_key = get_public_key(hd_path)?;

    log::info!("{:?}", public_key);
    log::info!("ed25519:{}", public_key.as_bytes().to_base58());

    Ok(())
}
