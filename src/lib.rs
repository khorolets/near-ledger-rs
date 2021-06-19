use ledger::TransportNativeHID;
use ledger_apdu::map_apdu_error_description;
use ledger_transport::errors::TransportError;
use ledger_transport::{APDUCommand, APDUTransport};

const CLA: u8 = 0x80; // Instruction class
const INS_GET_PUBLIC_KEY: u8 = 4; // Instruction code to get public key
const INS_GET_VERSION: u8 = 6; // Instruction code to get app version from the Ledger
const INS_SIGN_TRANSACTION: u8 = 2; // Instruction code to sign a transaction on the Ledger
const NETWORK_ID: u8 = 'W' as u8; // Instruction parameter 2
const RETURN_CODE_OK: u16 = 36864; // APDUAnswer.retcode which means success from Ledger
const CHUNK_SIZE: usize = 128; // Chunk size to be sent to Ledger

pub type BorshSerializedUnsignedTransaction = Vec<u8>;
pub type NEARLedgerAppVersion = Vec<u8>;
pub type SignatureBytes = Vec<u8>;

#[derive(Debug)]
pub enum NEARLedgerError {
    DeviceNotFound,
    APDUExchangeError(String),
    APDUTransportError(TransportError),
}

/// Converts BIP32Path into bytes (Vec<u8>)
fn hd_path_to_bytes(hd_path: &slip10::BIP32Path) -> Vec<u8> {
    (0..hd_path.depth())
        .map(|index| {
            let value = *hd_path.index(index).unwrap();
            value.to_be_bytes()
        })
        .flatten()
        .collect::<Vec<u8>>()
}

pub async fn get_version() -> Result<NEARLedgerAppVersion, NEARLedgerError> {
    // instantiate the connection to Ledger
    // will return an error if Ledger is not connected
    let transport = match TransportNativeHID::new() {
        Ok(transport) => APDUTransport::new(transport),
        // TODO: refactor this
        // https://github.com/Zondax/ledger-rs/issues/65
        Err(_err) => return Err(NEARLedgerError::DeviceNotFound),
    };

    match transport
        .exchange(&APDUCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0, // Instruction parameter 1 (offset)
            p2: 0,
            data: vec![],
        })
        .await
    {
        Ok(response) => {
            // Ok means we successfully exchanged with the Ledger
            // but doesn't mean our request succeeded
            // we need to check it based on `response.retcode`
            if response.retcode == RETURN_CODE_OK {
                return Ok(response.data);
            } else {
                let error_string = map_apdu_error_description(response.retcode).to_string();
                return Err(NEARLedgerError::APDUExchangeError(error_string));
            }
        }
        Err(err) => return Err(NEARLedgerError::APDUTransportError(err)),
    };
}

/// Gets PublicKey from the Ledger on the given `hd_path`
pub async fn get_public_key(
    hd_path: slip10::BIP32Path,
) -> Result<ed25519_dalek::PublicKey, NEARLedgerError> {
    // instantiate the connection to Ledger
    // will return an error if Ledger is not connected
    let transport = match TransportNativeHID::new() {
        Ok(transport) => APDUTransport::new(transport),
        // TODO: refactor this
        // https://github.com/Zondax/ledger-rs/issues/65
        Err(_err) => return Err(NEARLedgerError::DeviceNotFound),
    };

    // hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&hd_path);

    match transport
        .exchange(&APDUCommand {
            cla: CLA,
            ins: INS_GET_PUBLIC_KEY,
            p1: 0, // Instruction parameter 1 (offset)
            p2: NETWORK_ID,
            data: hd_path_bytes,
        })
        .await
    {
        Ok(response) => {
            // Ok means we successfully exchanged with the Ledger
            // but doesn't mean our request succeeded
            // we need to check it based on `response.retcode`
            if response.retcode == RETURN_CODE_OK {
                return Ok(ed25519_dalek::PublicKey::from_bytes(&response.data).unwrap());
            } else {
                let error_string = map_apdu_error_description(response.retcode).to_string();
                return Err(NEARLedgerError::APDUExchangeError(error_string));
            }
        }
        Err(err) => return Err(NEARLedgerError::APDUTransportError(err)),
    };
}

pub async fn sign_transaction(
    unsigned_transaction_borsh_serializer: BorshSerializedUnsignedTransaction,
    seed_phrase_hd_path: slip10::BIP32Path,
) -> Result<SignatureBytes, NEARLedgerError> {
    // instantiate the connection to Ledger
    // will return an error if Ledger is not connected
    let transport = match TransportNativeHID::new() {
        Ok(transport) => APDUTransport::new(transport),
        // TODO: refactor this
        // https://github.com/Zondax/ledger-rs/issues/65
        Err(_err) => return Err(NEARLedgerError::DeviceNotFound),
    };

    // seed_phrase_hd_path must be converted into bytes to be sent as `data` to the Ledger
    let hd_path_bytes = hd_path_to_bytes(&seed_phrase_hd_path);

    let mut data: Vec<u8> = vec![];
    data.extend(hd_path_bytes);
    data.extend(unsigned_transaction_borsh_serializer);

    let chunks = data.chunks(CHUNK_SIZE);
    let chunks_count = chunks.len();

    for (i, chunk) in chunks.enumerate() {
        let is_last_chunk = chunks_count == i + 1;
        match transport
            .exchange(&APDUCommand {
                cla: CLA,
                ins: INS_SIGN_TRANSACTION,
                p1: if is_last_chunk { 0x80 } else { 0 }, // Instruction parameter 1 (offset)
                p2: NETWORK_ID,
                data: chunk.to_vec(),
            })
            .await
        {
            Ok(response) => {
                // Ok means we successfully exchanged with the Ledger
                // but doesn't mean our request succeeded
                // we need to check it based on `response.retcode`
                if response.retcode == RETURN_CODE_OK {
                    if is_last_chunk {
                        return Ok(response.data);
                    }
                } else {
                    let error_string = map_apdu_error_description(response.retcode).to_string();
                    return Err(NEARLedgerError::APDUExchangeError(error_string));
                }
            }
            Err(err) => return Err(NEARLedgerError::APDUTransportError(err)),
        };
    }
    Err(NEARLedgerError::APDUExchangeError(
        "Unable to process request".to_owned(),
    ))
}
