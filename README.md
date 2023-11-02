# near-ledger-rs

[![Rust](https://github.com/khorolets/near-ledger-rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/khorolets/near-ledger-rs/actions/workflows/rust.yml)
[![](http://meritbadge.herokuapp.com/near-ledger)](https://crates.io/crates/near-ledger)
[![]( https://docs.rs/near-ledger/badge.svg)]( https://docs.rs/near-ledger/)

It is NEAR <-> Ledger transport


Provides a set of commands that can be executed to communicate with NEAR App installed on Ledger device:

* Read PublicKey from Ledger device by HD Path
* Sign a Transaction


## Examples


### Get PublicKey from Ledger


```rust
use near_ledger::get_public_key;
use slip10::BIP32Path;

let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
let public_key = match get_public_key(hd_path)
   .await
   .map_err(|near_ledger_error| {
       panic!(
           "An error occurred while getting PublicKey from Ledger device: {:?}",
            near_ledger_error,
       )
   })?;
```


#### Trick


To convert the answer into `near_crypto::PublicKey` do:

```rust
near_crypto::PublicKey::ED25519(
    near_crypto::ED25519PublicKey::from(
        public_key.to_bytes(),
    )
)
```


### How to sign a transaction


```rust
use near_ledger::sign_transaction;
use borsh::BorshSerializer;
use slip10::BIP32Path;
asyn fn main() {
let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
let borsh_transaction = near_unsigned_transaction.try_to_vec().unwrap();
let signature = match sign_transaction(borsh_transaction, hd_path)
   .await
   .map_err(|near_ledger_error| {
       panic!(
           "An error occurred while getting PublicKey from Ledger device: {:?}",
            near_ledger_error,
       )
   })?;
```


#### Trick

To convert the answer into `near_crypto::Signature` do:


```rust
near_crypto::Signature::from_parts(near_crypto::KeyType::ED25519, &signature)
    .expect("Signature is not expected to fail on deserialization")
```

## Executable examples

### Get version

```bash
RUST_LOG=get_version,near_ledger=info cargo run --example get_version
```

### Get PublicKey from Ledger

```bash
RUST_LOG=get_public_key,near_ledger=info cargo run --example get_public_key
```

### Sign a transaction

```bash
RUST_LOG=sign_transaction,near_ledger=info cargo run --example sign_transaction
```



