use crate::{
  helpers::sha256_hasher,
  types::{Keys, Unit},
};

struct Keyset {
  id: String,
  unit: Unit,
  keys: Keys,
}

fn derive_keyset_id(keys: Keys) -> String {
  let mut sorted_keys = Vec::from_iter(keys);
  sorted_keys.sort_by(|&(a, _), &(b, _)| a.cmp(&b));
  let pubkeys: Vec<Vec<u8>> = sorted_keys
    .iter()
    .map(|&(_, pubkey)| pubkey.serialize().to_vec())
    .collect();
  let pubkeys_concat = pubkeys.concat();
  let pubkeys_hashed = sha256_hasher(pubkeys_concat);

  let hex_encoded = hex::encode(pubkeys_hashed);

  format!("00{}", &hex_encoded[..14])
}
