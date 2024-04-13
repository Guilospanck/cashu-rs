use serde::{Deserialize, Serialize};

use crate::{
  constants::KEYSET_ID_VERSION,
  helpers::{generate_key_pair, sha256_hasher},
  types::{Keys, Unit},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Keyset {
  pub id: String,
  pub unit: Unit,
  pub active: bool,
}

pub type Keysets = Vec<Keyset>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeysetWithKeys {
  pub id: String,
  pub unit: Unit,
  pub active: bool,
  pub keys: Keys,
}

impl KeysetWithKeys {
  pub fn new(unit: Unit, keys: &Keys) -> Self {
    let id = derive_keyset_id(keys.clone());

    Self {
      id,
      unit,
      active: true,
      keys: keys.clone(),
    }
  }
}

/// 1 - sort public keys by their amount in ascending order
/// 2 - concatenate all public keys to one byte array
/// 3 - HASH_SHA256 the concatenated public keys
/// 4 - take the first 14 characters of the hex-encoded hash
/// 5 - prefix it with a keyset ID version byte
pub fn derive_keyset_id(keys: Keys) -> String {
  let mut sorted_keys = Vec::from_iter(keys);
  sorted_keys.sort_by(|&(a, _), &(b, _)| a.cmp(&b));
  let pubkeys: Vec<Vec<u8>> = sorted_keys
    .iter()
    .map(|&(_, pubkey)| pubkey.serialize().to_vec())
    .collect();
  let pubkeys_concat = pubkeys.concat();
  let pubkeys_hashed = sha256_hasher(pubkeys_concat);

  let hex_encoded = hex::encode(pubkeys_hashed);

  format!("{}{}", KEYSET_ID_VERSION, &hex_encoded[..14])
}

/// Each keyset is identified by its keyset id
/// which can be computed by anyone from its public keys
/// using `[derive_keyset_id]` keyset fn.
pub fn generate_keyset() -> KeysetWithKeys {
  let (_, k1) = generate_key_pair();
  let (_, k2) = generate_key_pair();
  let (_, k3) = generate_key_pair();
  let (_, k4) = generate_key_pair();
  let (_, k5) = generate_key_pair();
  let (_, k6) = generate_key_pair();
  let (_, k7) = generate_key_pair();
  let (_, k8) = generate_key_pair();
  let (_, k9) = generate_key_pair();
  let (_, k10) = generate_key_pair();
  let (_, k11) = generate_key_pair();

  let mut keys = Keys::new();
  keys.insert(1, k1);
  keys.insert(2, k2);
  keys.insert(4, k3);
  keys.insert(8, k4);
  keys.insert(16, k5);
  keys.insert(32, k6);
  keys.insert(64, k7);
  keys.insert(128, k8);
  keys.insert(256, k9);
  keys.insert(512, k10);
  keys.insert(1024, k11);

  let id = derive_keyset_id(keys.clone());

  KeysetWithKeys {
    id,
    unit: Unit::SAT,
    active: true,
    keys: keys.clone(),
  }
}

#[cfg(test)]
mod tests {

  use super::*;
  use bitcoin::secp256k1::PublicKey;
  use std::str::FromStr;

  #[test]
  fn should_derive_keyset_id_correctly() {
    // arrange
    let k1 =
      PublicKey::from_str("03bffbb7550d4464afa24fb0d6ae9a4ab437e93aa710f103170a4504bfb9ba8f0e")
        .unwrap();
    let k2 =
      PublicKey::from_str("03f7a3beef79667abd4f0e1cc59a7a73528db8adb9017d2a040d35fd0bc324ac1e")
        .unwrap();
    let k3 =
      PublicKey::from_str("03bff4d95569a355dea0663a4bf97e2e6a3ebbf243b40c985252172fd5c2e707ea")
        .unwrap();

    let pubkeys_concatenated = [
      k1.serialize().to_vec(),
      k2.serialize().to_vec(),
      k3.serialize().to_vec(),
    ]
    .concat();
    let pubkeys_hashed = sha256_hasher(pubkeys_concatenated);
    let hex_encoded = hex::encode(pubkeys_hashed);

    let mut keys = Keys::new();
    keys.insert(1, k1);
    keys.insert(2, k2);
    keys.insert(4, k3);

    // act
    let id = derive_keyset_id(keys);

    // assert
    assert!(id.starts_with(KEYSET_ID_VERSION));
    assert_eq!(id.len(), 16);
    assert_eq!(&id[2..], &hex_encoded[..14])
  }
}
