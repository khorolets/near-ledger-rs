//! NEAR <-> Ledger transport
//!
//! Provides a set of commands that can be executed to communicate with NEAR App installed on Ledger device:
//! - Read PublicKey from Ledger device by HD Path
//! - Sign a Transaction
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use ledger_apdu::APDUAnswer;
use ledger_transport::APDUCommand;
use ledger_transport_hid::{
    hidapi::{HidApi, HidError},
    LedgerHIDError, TransportNativeHID,
};
use near_primitives::action::delegate::DelegateAction;
use near_primitives_core::borsh::{self, BorshSerialize};

const CLA: u8 = 0x80; // Instruction class
const INS_GET_PUBLIC_KEY: u8 = 4; // Instruction code to get public key
const INS_GET_WALLET_ID: u8 = 0x05; // Get Wallet ID
const INS_GET_VERSION: u8 = 6; // Instruction code to get app version from the Ledger
const INS_SIGN_TRANSACTION: u8 = 2; // Instruction code to sign a transaction on the Ledger
const INS_SIGN_NEP413_MESSAGE: u8 = 7; // Instruction code to sign a nep-413 message with Ledger
const INS_SIGN_NEP366_DELEGATE_ACTION: u8 = 8; // Instruction code to sign a nep-413 message with Ledger
const NETWORK_ID: u8 = b'W'; // Instruction parameter 2
const RETURN_CODE_OK: u16 = 36864; // APDUAnswer.retcode which means success from Ledger
const CHUNK_SIZE: usize = 250; // Chunk size to be sent to Ledger

/// Alias of `Vec<u8>`. The goal is naming to help understand what the bytes to deal with
pub type BorshSerializedUnsignedTransaction = Vec<u8>;

const P1_GET_PUB_DISPLAY: u8 = 0;
const P1_GET_PUB_SILENT: u8 = 1;

const P1_SIGN_NORMAL: u8 = 0;
const P1_SIGN_NORMAL_LAST_CHUNK: u8 = 0x80;

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
    /// Error with transport
    LedgerHIDError(LedgerHIDError),
}

/// Converts BIP32Path into bytes (`Vec<u8>`)
fn hd_path_to_bytes(hd_path: &slipped10::BIP32Path) -> Vec<u8> {
    (0..hd_path.depth())
        .flat_map(|index| {
            let value = *hd_path.index(index).unwrap();
            value.to_be_bytes()
        })
        .collect::<Vec<u8>>()
}

#[inline(always)]
fn log_command(index: usize, is_last_chunk: bool, command: &APDUCommand<Vec<u8>>) {
    log::info!(
        "APDU  in{}: {}",
        if is_last_chunk {
            " (last)".to_string()
        } else {
            format!(" ({})", index)
        },
        hex::encode(command.serialize())
    );
}

/// Get the version of NEAR App installed on Ledger
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an `NEARLedgerAppVersion` (just a `Vec<u8>` for now, where first value is a major version, second is a minor and the last is the path)
///  and whose `Err` value is a `NEARLedgerError` containing an error which occurred.
pub fn get_version() -> Result<NEARLedgerAppVersion, NEARLedgerError> {
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

    log::info!("APDU  in: {}", hex::encode(command.serialize()));

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
                Err(NEARLedgerError::APDUExchangeError(error_string))
            }
        }
        Err(err) => Err(NEARLedgerError::LedgerHIDError(err)),
    }
}

/// Gets PublicKey from the Ledger on the given `hd_path`
///
/// # Inputs
/// * `hd_path` - seed phrase hd path `slipped10::BIP32Path` for which PublicKey to look
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an `ed25519_dalek::VerifyingKey` and whose `Err` value is a
///   `NEARLedgerError` containing an error which
///   occurred.
///
/// # Examples
///
/// ```no_run
/// use near_ledger::get_public_key;
/// use slipped10::BIP32Path;
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
/// # let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).unwrap();
/// let public_key = near_crypto::PublicKey::ED25519(
///     near_crypto::ED25519PublicKey::from(
///         public_key.to_bytes(),
///     )
/// );
/// ```
pub fn get_public_key(
    hd_path: slipped10::BIP32Path,
) -> Result<ed25519_dalek::VerifyingKey, NEARLedgerError> {
    get_public_key_with_display_flag(hd_path, true)
}

pub fn get_public_key_with_display_flag(
    hd_path: slipped10::BIP32Path,
    display_and_confirm: bool,
) -> Result<ed25519_dalek::VerifyingKey, NEARLedgerError> {
    // instantiate the connection to Ledger
    // will return an error if Ledger is not connected
    let transport = get_transport()?;

    // hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&hd_path);

    let p1 = if display_and_confirm {
        P1_GET_PUB_DISPLAY
    } else {
        P1_GET_PUB_SILENT
    };

    let command = APDUCommand {
        cla: CLA,
        ins: INS_GET_PUBLIC_KEY,
        p1, // Instruction parameter 1 (offset)
        p2: NETWORK_ID,
        data: hd_path_bytes,
    };
    log::info!("APDU  in: {}", hex::encode(command.serialize()));

    match transport.exchange(&command) {
        Ok(response) => handle_public_key_response(response),
        Err(err) => Err(NEARLedgerError::LedgerHIDError(err)),
    }
}

pub fn get_wallet_id(
    hd_path: slipped10::BIP32Path,
) -> Result<ed25519_dalek::VerifyingKey, NEARLedgerError> {
    // instantiate the connection to Ledger
    // will return an error if Ledger is not connected
    let transport = get_transport()?;

    // hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&hd_path);

    let command = APDUCommand {
        cla: CLA,
        ins: INS_GET_WALLET_ID,
        p1: 0, // Instruction parameter 1 (offset)
        p2: NETWORK_ID,
        data: hd_path_bytes,
    };
    log::info!("APDU  in: {}", hex::encode(command.serialize()));

    match transport.exchange(&command) {
        Ok(response) => handle_public_key_response(response),
        Err(err) => Err(NEARLedgerError::LedgerHIDError(err)),
    }
}

fn handle_public_key_response(
    response: APDUAnswer<Vec<u8>>,
) -> Result<ed25519_dalek::VerifyingKey, NEARLedgerError> {
    log::info!(
        "APDU out: {}\nAPDU ret code: {:x}",
        hex::encode(response.apdu_data()),
        response.retcode(),
    );
    // Ok means we successfully exchanged with the Ledger
    // but doesn't mean our request succeeded
    // we need to check it based on `response.retcode`
    if response.retcode() == RETURN_CODE_OK {
        let data = response.data();
        if data.len() != PUBLIC_KEY_LENGTH {
            return Err(NEARLedgerError::APDUExchangeError(format!(
                "`{}` response obtained of invalid length {} != {} (expected)",
                hex::encode(data),
                data.len(),
                PUBLIC_KEY_LENGTH
            )));
        }
        let mut bytes: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        bytes.copy_from_slice(data);

        Ok(ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap())
    } else {
        let retcode = response.retcode();

        let error_string = format!("Ledger APDU retcode: 0x{:X}", retcode);
        Err(NEARLedgerError::APDUExchangeError(error_string))
    }
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
/// * `seed_phrase_hd_path` - seed phrase hd path `slipped10::BIP32Path` with which to sign
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
/// use near_primitives::{borsh, borsh::BorshSerialize};
/// use slipped10::BIP32Path;
/// use std::str::FromStr;
///
/// # fn main() {
/// # let near_unsigned_transaction = [10; 250];
/// let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
/// let borsh_transaction = borsh::to_vec(&near_unsigned_transaction).unwrap();
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
    seed_phrase_hd_path: slipped10::BIP32Path,
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
                P1_SIGN_NORMAL_LAST_CHUNK
            } else {
                P1_SIGN_NORMAL
            }, // Instruction parameter 1 (offset)
            p2: NETWORK_ID,
            data: chunk.to_vec(),
        };
        log_command(i, is_last_chunk, &command);
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

#[derive(Debug, BorshSerialize)]
#[borsh(crate = "near_primitives_core::borsh")]
pub struct NEP413Payload {
    pub messsage: String,
    pub nonce: [u8; 32],
    pub recipient: String,
    pub callback_url: Option<String>,
}

pub fn sign_message_nep413(
    payload: &NEP413Payload,
    seed_phrase_hd_path: slipped10::BIP32Path,
) -> Result<SignatureBytes, NEARLedgerError> {
    let transport = get_transport()?;
    // seed_phrase_hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&seed_phrase_hd_path);

    let mut data: Vec<u8> = vec![];
    data.extend(hd_path_bytes);
    data.extend_from_slice(&borsh::to_vec(payload).unwrap());

    let chunks = data.chunks(CHUNK_SIZE);
    let chunks_count = chunks.len();

    for (i, chunk) in chunks.enumerate() {
        let is_last_chunk = chunks_count == i + 1;
        let command = APDUCommand {
            cla: CLA,
            ins: INS_SIGN_NEP413_MESSAGE,
            p1: if is_last_chunk {
                P1_SIGN_NORMAL_LAST_CHUNK
            } else {
                P1_SIGN_NORMAL
            }, // Instruction parameter 1 (offset)
            p2: NETWORK_ID,
            data: chunk.to_vec(),
        };
        log_command(i, is_last_chunk, &command);
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

pub fn sign_message_nep366_delegate_action(
    payload: &DelegateAction,
    seed_phrase_hd_path: slipped10::BIP32Path,
) -> Result<SignatureBytes, NEARLedgerError> {
    let transport = get_transport()?;
    // seed_phrase_hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&seed_phrase_hd_path);

    let mut data: Vec<u8> = vec![];
    data.extend(hd_path_bytes);
    data.extend_from_slice(&borsh::to_vec(payload).unwrap());

    let chunks = data.chunks(CHUNK_SIZE);
    let chunks_count = chunks.len();

    for (i, chunk) in chunks.enumerate() {
        let is_last_chunk = chunks_count == i + 1;
        let command = APDUCommand {
            cla: CLA,
            ins: INS_SIGN_NEP366_DELEGATE_ACTION,
            p1: if is_last_chunk {
                P1_SIGN_NORMAL_LAST_CHUNK
            } else {
                P1_SIGN_NORMAL
            }, // Instruction parameter 1 (offset)
            p2: NETWORK_ID,
            data: chunk.to_vec(),
        };
        log_command(i, is_last_chunk, &command);
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
