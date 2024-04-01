use std::result;

use serde::{Deserialize, Serialize};

use bitcoin::{
  key::Secp256k1,
  secp256k1::{PublicKey, SecretKey, Scalar},
};

use crate::{helpers::{generate_key_pair, hash_to_curve}, types::{BlindSignature, BlindedMessage}};

/// [`Mint`] error
#[derive(thiserror::Error, Debug)]
pub enum MintError {
  #[error("Invalid URL params: `{0}`")]
  InvalidURLParams(String),
  #[error("Bad request: `{0}`")]
  BadRequest(String),
  #[error("API error: `{0}`")]
  APIError(String),
  #[error("JSON parse error: `{0}`")]
  JSONParseError(String),
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

  // Signs blinded message (an output)
  pub fn mint_or_swap_tokens(&self, message: BlindedMessage) -> Result<BlindSignature> {
    let BlindedMessage { b, id, amount } = message;

    let secp = Secp256k1::new();
    let scalar = Scalar::from(self.secretkey);
    // calculate C_ = kB_
    let c_ = b.mul_tweak(&secp, &scalar).expect("EC math could not mul_tweak");

    // Bob sends back to Alice blinded key (promise): C_ = kB_ (these two steps are the DH -blind- key exchange) (signing)
    Ok(BlindSignature { amount, id, c: c_ })
  }

  // checks that k*hash_to_curve(x) == C
  pub fn verification(&self, x: Vec<u8>, c: PublicKey) -> bool {
    let y = hash_to_curve(x);
    let secp = Secp256k1::new();
    let scalar = Scalar::from(self.secretkey);
    // calculate kY
    let ky = y.mul_tweak(&secp, &scalar).expect("EC math could not mul_tweak");
    c == ky
  }
}