use std::result;

use serde::{Deserialize, Serialize};

use bitcoin::{
  key::Secp256k1,
  secp256k1::{PublicKey, Scalar, SecretKey},
};

use crate::{
  helpers::{generate_key_pair, hash_to_curve},
  keyset::{generate_keyset, Keyset, KeysetWithKeys, Keysets},
  rest::{GetKeysResponse, GetKeysetsResponse},
  types::{BlindSignature, BlindedMessage},
};

/// [`Mint`] error
#[derive(thiserror::Error, Debug)]
pub enum MintError {
  #[error("Invalid EC math: `{0}`")]
  InvalidECMath(String),
}

type Result<T> = result::Result<T, MintError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Mint {
  secretkey: SecretKey,
  #[serde(rename = "K")]
  pub pubkey: PublicKey,
  keysets: Vec<KeysetWithKeys>,
}

impl Mint {
  // Publishes its public key `K`.
  pub fn new() -> Self {
    let keypair = generate_key_pair();

    let keyset = generate_keyset();

    Self {
      secretkey: keypair.0,
      pubkey: keypair.1,
      keysets: [keyset].to_vec(),
    }
  }

  /// A set of all Ks for a set of amounts is called a keyset.
  ///
  /// A mint responds only with its active keysets
  /// Active keysets are the ones that the mint can sign promises
  /// (blind signatures) with it.
  ///
  /// The mint will accept tokens from inactive keysets as inputs
  /// (proofs) but will not sign with them for new outputs
  /// (blinded messages).
  ///
  /// /v1/keys
  pub fn get_v1_keys(&self) -> GetKeysResponse {
    let active_keysets: Vec<KeysetWithKeys> = self
      .keysets
      .clone()
      .into_iter()
      .filter(|x| x.active)
      .collect();

    GetKeysResponse {
      keysets: active_keysets,
    }
  }

  /// /v1/keys/{keyset_id}
  pub fn get_v1_keys_keyset_id(&self, keyset_id: String) -> GetKeysResponse {
    let mut keysets_with_keys: Vec<KeysetWithKeys> = vec![];

    if let Some(keyset) = self
       .keysets
       .clone()
       .into_iter()
       .find(|KeysetWithKeys { id, .. }| *id == keyset_id) { keysets_with_keys.push(keyset) };

    GetKeysResponse { keysets: keysets_with_keys }
  }

  /// /v1/keysets
  pub fn get_v1_keysets(&self) -> GetKeysetsResponse {
    let mut keysets: Keysets = vec![];
    self.keysets.clone().into_iter().for_each(
      |KeysetWithKeys {
         id, unit, active, ..
       }| keysets.push(Keyset { id, unit, active }),
    );

    GetKeysetsResponse { keysets }
  }

  // Signs blinded message (an output)
  pub fn mint_or_swap_tokens(&self, message: BlindedMessage) -> Result<BlindSignature> {
    let BlindedMessage { b, id, amount } = message;

    let secp = Secp256k1::new();
    let scalar = Scalar::from(self.secretkey);
    // calculate C_ = kB_
    let c_ = match b.mul_tweak(&secp, &scalar) {
      Ok(c) => c,
      Err(e) => return Err(MintError::InvalidECMath(format!("[mul_tweak|mint] {}", e))),
    };

    // Bob sends back to Alice blinded key (promise): C_ = kB_ (these two steps are the DH -blind- key exchange) (signing)
    Ok(BlindSignature { amount, id, c: c_ })
  }

  // checks that k*hash_to_curve(x) == C
  pub fn verification(&self, x: Vec<u8>, c: PublicKey) -> Result<bool> {
    let y = hash_to_curve(x);
    let secp = Secp256k1::new();
    let scalar = Scalar::from(self.secretkey);
    // calculate kY
    let ky = match y.mul_tweak(&secp, &scalar) {
      Ok(value) => value,
      Err(e) => {
        return Err(MintError::InvalidECMath(format!(
          "[mul_tweak|verification] {}",
          e
        )))
      }
    };

    Ok(c == ky)
  }
}
