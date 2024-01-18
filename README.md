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
use std::str::FromStr;

let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
let public_key = get_public_key(hd_path).unwrap();
println!("{:#?}", public_key);
```


#### Trick


To convert the answer into `near_crypto::PublicKey` do:

```rust
let public_key = near_crypto::PublicKey::ED25519(
    near_crypto::ED25519PublicKey::from(
        public_key.to_bytes(),
    )
);
```


### How to sign a transaction


```rust
use near_ledger::{sign_transaction, SignTarget};
use near_primitives::borsh::BorshSerialize;
use slip10::BIP32Path;
use std::str::FromStr;

let hd_path = BIP32Path::from_str("44'/397'/0'/0'/1'").unwrap();
let borsh_transaction = near_unsigned_transaction.try_to_vec().unwrap();
let signature = sign_transaction(SignTarget::BorshUnsignedTx(borsh_transaction), hd_path).unwrap();
println!("{:#?}", signature);
```


#### Trick

To convert the answer into `near_crypto::Signature` do:


```rust
let signature = near_crypto::Signature::from_parts(near_crypto::KeyType::ED25519, &signature)
    .expect("Signature is not expected to fail on deserialization");
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

#### Transfer

```bash
RUST_LOG=sign_transfer,near_ledger=info cargo run --example sign_transfer
```

### Blind sign a transaction

```bash
RUST_LOG=blind_sign_transaction,near_ledger=info cargo run --example blind_sign_transaction
```
