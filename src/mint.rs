use std::result;

use serde::{Deserialize, Serialize};

use bitcoin::{
  key::Secp256k1,
  secp256k1::{PublicKey, Scalar, SecretKey},
};

use crate::{
  helpers::{generate_key_pair, hash_to_curve}, rest::{GetKeysResponse, GetKeysetsResponse}, types::{BlindSignature, BlindedMessage}
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
}

impl Mint {
  // Publishes its public key `K`.
  pub fn new() -> Self {
    let keypair = generate_key_pair();

    Self {
      secretkey: keypair.0,
      pubkey: keypair.1,
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
  pub fn get_v1_keys(&self) -> GetKeysResponse {
    // TODO: return active keys
    unimplemented!()
  }

  pub fn get_v1_keys_keyset_id(&self, _keyset_id: String) -> GetKeysResponse {
    // TODO: return keyset that matches the keyset_id
    unimplemented!()
  }

  pub fn get_v1_keysets(&self) -> GetKeysetsResponse {
    // TODO: return keysets
    unimplemented!()
  }

  /// Each keyset is identified by its keyset id
  /// which can be computed by anyone from its public keys
  /// using `[derive_keyset_id]` keyset fn.
  fn generate_keyset(&self) {
    // TODO
    unimplemented!()
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
