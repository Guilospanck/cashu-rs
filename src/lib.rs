use secp256k1::{Parity, PublicKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

struct Mint {}

struct Wallet {}

const DOMAIN_SEPARATOR: &[u8] = "Secp256k1_HashToCurve_Cashu_".as_bytes();

fn sha256_hasher(data: Vec<u8>) -> Vec<u8> {
  let mut hasher = Sha256::new();
  hasher.update(data);
  hasher.finalize()[..].to_vec()
}

fn _get_hashed_value(msg: Vec<u8>, counter: u32) -> Vec<u8> {
  let mut msg_to_hash = 0x02_u8.to_be_bytes().to_vec();
  msg_to_hash.extend(DOMAIN_SEPARATOR.to_vec());
  msg_to_hash.extend_from_slice(&msg);
  msg_to_hash.extend(counter.to_le_bytes());

  sha256_hasher(msg_to_hash)
}

pub fn hash_to_curve(x: Vec<u8>) -> PublicKey {
  let mut counter: u32 = 0;
  let mut msg_hash = _get_hashed_value(x.clone(), counter);

  loop {
    if let Ok(x_only_pubkey) = XOnlyPublicKey::from_slice(&msg_hash) {
      return PublicKey::from_x_only_public_key(x_only_pubkey, Parity::Even);
    };
    counter += 1;
    msg_hash = _get_hashed_value(x.clone(), counter);

  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let a = b"potato";
    hash_to_curve(a.to_vec());
    assert!(true);
  }
}
