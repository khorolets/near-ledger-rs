//! NEAR <-> Ledger transport
//!
//! Provides a set of commands that can be executed to communicate with NEAR App installed on Ledger device:
//! - Read PublicKey from Ledger device by HD Path
//! - Sign a Transaction
use ledger_transport::APDUCommand;
use ledger_transport_hid::{
    hidapi::{HidApi, HidError},
    LedgerHIDError, TransportNativeHID,
};
use near_primitives_core::hash::CryptoHash;

const CLA: u8 = 0x80; // Instruction class
const INS_GET_PUBLIC_KEY: u8 = 4; // Instruction code to get public key
const INS_GET_VERSION: u8 = 6; // Instruction code to get app version from the Ledger
const INS_SIGN_TRANSACTION: u8 = 2; // Instruction code to sign a transaction on the Ledger
const NETWORK_ID: u8 = 'W' as u8; // Instruction parameter 2
const RETURN_CODE_OK: u16 = 36864; // APDUAnswer.retcode which means success from Ledger
const CHUNK_SIZE: usize = 128; // Chunk size to be sent to Ledger

/// Alias of `Vec<u8>`. The goal is naming to help understand what the bytes to deal with
pub type BorshSerializedUnsignedTransaction = Vec<u8>;

const SIGN_NORMAL: u8 = 0;
const SIGN_NORMAL_LAST_CHUNK: u8 = 0x80;
const SIGN_BLIND: u8 = 1;

// this is value from LedgerHQ/app-near repo
const SW_INCORRECT_P1_P2: u16 = 0x6A86;
// this is value from LedgerHQ/app-near repo
const SW_BUFFER_OVERFLOW: u16 = 0x6990;

// this is value from LedgerHQ/app-near repo
const SW_SETTING_BLIND_DISABLED: u16 = 0x6192;

/// Alias of `Vec<u8>`. The goal is naming to help understand what the bytes to deal with
pub type NEARLedgerAppVersion = Vec<u8>;
/// Alias of `Vec<u8>`. The goal is naming to help understand what the bytes to deal with
pub type SignatureBytes = Vec<u8>;

#[derive(Debug)]
pub enum NEARLedgerError {
    /// Error occuring on init of hidapid and getting current devices list
    HidApiError(HidError),
    /// Error occuring on creating a new hid transport, connecting to first ledger device found  
    LedgerHidError(LedgerHIDError),
    /// Error occurred while exchanging with Ledger device
    APDUExchangeError(String),
    /// Blind signature not supported
    BlindSignatureNotSupported,
    /// Blind signature disabled in ledger's app settings
    BlindSignatureDisabled,
    /// Error with transport
    LedgerHIDError(LedgerHIDError),
    /// Transaction is too large to be signed
    BufferOverflow(OnlyBlindSigning),
}

#[derive(Debug, PartialEq, Eq)]
pub struct OnlyBlindSigning {
    pub byte_array: CryptoHash,
}

impl OnlyBlindSigning {
    fn hash_bytes(bytes: &[u8]) -> Self {
        Self {
            byte_array: CryptoHash::hash_bytes(bytes),
        }
    }
}

/// Converts BIP32Path into bytes (`Vec<u8>`)
fn hd_path_to_bytes(hd_path: &slip10::BIP32Path) -> Vec<u8> {
    (0..hd_path.depth())
        .map(|index| {
            let value = *hd_path.index(index).unwrap();
            value.to_be_bytes()
        })
        .flatten()
        .collect::<Vec<u8>>()
}

/// Get the version of NEAR App installed on Ledger
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an `NEARLedgerAppVersion` (just a `Vec<u8>` for now, where first value is a major version, second is a minor and the last is the path)
///  and whose `Err` value is a `NEARLedgerError` containing an error which occurred.
pub fn get_version() -> Result<NEARLedgerAppVersion, NEARLedgerError> {
    //! Something
    // instantiate the connection to Ledger
    // will return an error if Ledger is not connected
    let transport = get_transport()?;
    let command = APDUCommand {
        cla: CLA,
        ins: INS_GET_VERSION,
        p1: 0, // Instruction parameter 1 (offset)
        p2: 0,
        data: vec![],
    };

    log::info!("APDU  in: {}", hex::encode(&command.serialize()));

    match transport.exchange(&command) {
        Ok(response) => {
            log::info!(
                "APDU out: {}\nAPDU ret code: {:x}",
                hex::encode(response.apdu_data()),
                response.retcode(),
            );
            // Ok means we successfully exchanged with the Ledger
            // but doesn't mean our request succeeded
            // we need to check it based on `response.retcode`
            if response.retcode() == RETURN_CODE_OK {
                return Ok(response.data().to_vec());
            } else {
                let retcode = response.retcode();

                let error_string = format!("Ledger APDU retcode: 0x{:X}", retcode);
                return Err(NEARLedgerError::APDUExchangeError(error_string));
            }
        }
        Err(err) => return Err(NEARLedgerError::LedgerHIDError(err)),
    };
}

/// Gets PublicKey from the Ledger on the given `hd_path`
///
/// # Inputs
/// * `hd_path` - seed phrase hd path `slip10::BIP32Path` for which PublicKey to look
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an `ed25519_dalek::PublicKey` and whose `Err` value is a
///   `NEARLedgerError` containing an error which
///   occurred.
///
/// # Examples
///
/// ```no_run
/// use near_ledger::get_public_key;
/// use slip10::BIP32Path;
/// use std::str::FromStr;
///
/// # fn main() {
/// let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
/// let public_key = get_public_key(hd_path).unwrap();
/// println!("{:#?}", public_key);
/// # }
/// ```
///
/// # Trick
///
/// To convert the answer into `near_crypto::PublicKey` do:
///
/// ```
/// # let public_key_bytes = [10u8; 32];
/// # let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key_bytes).unwrap();
/// let public_key = near_crypto::PublicKey::ED25519(
///     near_crypto::ED25519PublicKey::from(
///         public_key.to_bytes(),
///     )
/// );
/// ```
pub fn get_public_key(
    hd_path: slip10::BIP32Path,
) -> Result<ed25519_dalek::PublicKey, NEARLedgerError> {
    // instantiate the connection to Ledger
    // will return an error if Ledger is not connected
    let transport = get_transport()?;

    // hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&hd_path);

    let command = APDUCommand {
        cla: CLA,
        ins: INS_GET_PUBLIC_KEY,
        p1: 0, // Instruction parameter 1 (offset)
        p2: NETWORK_ID,
        data: hd_path_bytes,
    };
    log::info!("APDU  in: {}", hex::encode(&command.serialize()));

    match transport.exchange(&command) {
        Ok(response) => {
            log::info!(
                "APDU out: {}\nAPDU ret code: {:x}",
                hex::encode(response.apdu_data()),
                response.retcode(),
            );
            // Ok means we successfully exchanged with the Ledger
            // but doesn't mean our request succeeded
            // we need to check it based on `response.retcode`
            if response.retcode() == RETURN_CODE_OK {
                return Ok(ed25519_dalek::PublicKey::from_bytes(&response.data()).unwrap());
            } else {
                let retcode = response.retcode();

                let error_string = format!("Ledger APDU retcode: 0x{:X}", retcode);
                return Err(NEARLedgerError::APDUExchangeError(error_string));
            }
        }
        Err(err) => return Err(NEARLedgerError::LedgerHIDError(err)),
    };
}

fn get_transport() -> Result<TransportNativeHID, NEARLedgerError> {
    // instantiate the connection to Ledger
    // will return an error if Ledger is not connected
    let hidapi = HidApi::new().map_err(NEARLedgerError::HidApiError)?;
    TransportNativeHID::new(&hidapi).map_err(NEARLedgerError::LedgerHidError)
}

/// Sign the transaction. Transaction should be [borsh serialized](https://github.com/near/borsh-rs) `Vec<u8>`
///
/// # Inputs
/// * `unsigned_transaction_borsh_serializer` - unsigned transaction `near_primitives::transaction::Transaction`
/// which is serialized with `BorshSerializer` and basically is just `Vec<u8>`
/// * `seed_phrase_hd_path` - seed phrase hd path `slip10::BIP32Path` with which to sign
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an `Signature` (bytes) and whose `Err` value is a
/// `NEARLedgerError` containing an error which occurred.
///
/// # Examples
///
/// ```no_run
/// use near_ledger::sign_transaction;
/// use near_primitives::borsh::BorshSerialize;
/// use slip10::BIP32Path;
/// use std::str::FromStr;
///
/// # fn main() {
/// # let near_unsigned_transaction = [10; 250];
/// let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
/// let borsh_transaction = near_unsigned_transaction.try_to_vec().unwrap();
/// let signature = sign_transaction(borsh_transaction, hd_path).unwrap();
/// println!("{:#?}", signature);
/// # }
/// ```
///
/// # Trick
///
/// To convert the answer into `near_crypto::Signature` do:
///
/// ```
/// # let signature = [10; 64].to_vec();
/// let signature = near_crypto::Signature::from_parts(near_crypto::KeyType::ED25519, &signature)
///     .expect("Signature is not expected to fail on deserialization");
/// ```
pub fn sign_transaction(
    unsigned_tx: BorshSerializedUnsignedTransaction,
    seed_phrase_hd_path: slip10::BIP32Path,
) -> Result<SignatureBytes, NEARLedgerError> {
    let transport = get_transport()?;
    // seed_phrase_hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&seed_phrase_hd_path);

    let mut data: Vec<u8> = vec![];
    data.extend(hd_path_bytes);
    data.extend(&unsigned_tx);

    let chunks = data.chunks(CHUNK_SIZE);
    let chunks_count = chunks.len();

    for (i, chunk) in chunks.enumerate() {
        let is_last_chunk = chunks_count == i + 1;
        let command = APDUCommand {
            cla: CLA,
            ins: INS_SIGN_TRANSACTION,
            p1: if is_last_chunk {
                SIGN_NORMAL_LAST_CHUNK
            } else {
                SIGN_NORMAL
            }, // Instruction parameter 1 (offset)
            p2: NETWORK_ID,
            data: chunk.to_vec(),
        };
        log::info!("APDU  in: {}", hex::encode(&command.serialize()));
        match transport.exchange(&command) {
            Ok(response) => {
                log::info!(
                    "APDU out: {}\nAPDU ret code: {:x}",
                    hex::encode(response.apdu_data()),
                    response.retcode(),
                );
                // Ok means we successfully exchanged with the Ledger
                // but doesn't mean our request succeeded
                // we need to check it based on `response.retcode`
                if response.retcode() == RETURN_CODE_OK {
                    if is_last_chunk {
                        return Ok(response.data().to_vec());
                    }
                } else {
                    let retcode = response.retcode();

                    if retcode == SW_BUFFER_OVERFLOW {
                        return Err(NEARLedgerError::BufferOverflow(
                            OnlyBlindSigning::hash_bytes(&unsigned_tx),
                        ));
                    }

                    let error_string = format!("Ledger APDU retcode: 0x{:X}", retcode);
                    return Err(NEARLedgerError::APDUExchangeError(error_string));
                }
            }
            Err(err) => return Err(NEARLedgerError::LedgerHIDError(err)),
        };
    }
    Err(NEARLedgerError::APDUExchangeError(
        "Unable to process request".to_owned(),
    ))
}

pub fn blind_sign_transaction(
    payload: OnlyBlindSigning,
    seed_phrase_hd_path: slip10::BIP32Path,
) -> Result<SignatureBytes, NEARLedgerError> {
    let transport = get_transport()?;
    // seed_phrase_hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&seed_phrase_hd_path);

    let mut data: Vec<u8> = vec![];
    data.extend(hd_path_bytes);
    data.extend(payload.byte_array.0);

    let command = APDUCommand {
        cla: CLA,
        ins: INS_SIGN_TRANSACTION,
        p1: SIGN_BLIND, // Instruction parameter 1 (offset)
        p2: NETWORK_ID,
        data,
    };
    log::info!("APDU  in: {}", hex::encode(&command.serialize()));
    match transport.exchange(&command) {
        Ok(response) => {
            log::info!(
                "APDU out: {}\nAPDU ret code: {:x}",
                hex::encode(response.apdu_data()),
                response.retcode(),
            );
            // Ok means we successfully exchanged with the Ledger
            // but doesn't mean our request succeeded
            // we need to check it based on `response.retcode`
            if response.retcode() == RETURN_CODE_OK {
                Ok(response.data().to_vec())
            } else {
                let retcode = response.retcode();
                if retcode == SW_INCORRECT_P1_P2 {
                    return Err(NEARLedgerError::BlindSignatureNotSupported);
                }
                if retcode == SW_SETTING_BLIND_DISABLED {
                    return Err(NEARLedgerError::BlindSignatureDisabled);
                }

                let error_string = format!("Ledger APDU retcode: 0x{:X}", retcode);
                Err(NEARLedgerError::APDUExchangeError(error_string))
            }
        }
        Err(err) => Err(NEARLedgerError::LedgerHIDError(err)),
    }
}
