use std::result;

use serde::{Deserialize, Serialize};

use crate::{
  helpers::{generate_key_pair, hash_to_curve},
  mint::Mint,
  types::{BlindSignature, BlindedMessage},
};

use bitcoin::{
  key::Secp256k1,
  secp256k1::{PublicKey, Scalar, SecretKey},
};

/// [`Wallet`] error
#[derive(thiserror::Error, Debug)]
pub enum WalletError {
  #[error("Invalid EC math: `{0}`")]
  InvalidECMath(String),
  #[error("Blind: `{0}`")]
  BlindError(String),
  #[error("Unblind: `{0}`")]
  UnblindError(String),
  #[error("Could not mint token: `{0}`")]
  CouldNotMintToken(String),
  #[error("Could not verify token: `{0}`")]
  CouldNotVerifyToken(String),
}

type Result<T> = result::Result<T, WalletError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {}

impl Wallet {
  pub fn new() -> Self {
    Self {}
  }

  pub fn begin(&self) -> Result<()> {
    // Mint Bob publishes public key K = kG
    let mint = Mint::new();

    // Picks secret x (utf-8 encoded 32 bytes encoded string) -- coin ID
    let (x, _) = generate_key_pair();
    let x = x.secret_bytes();

    // Get r, the blinding factor. r \in [0, (p-1)/2) <- part of the curve
    let (blinding_factor, _) = generate_key_pair();

    // Computes `B_ = Y + rG`, with r being a random blinding factor (blinding)
    let blinded_message = match self.blind(x.to_vec(), blinding_factor) {
      Ok(value) => value,
      Err(e) => return Err(WalletError::BlindError(e.to_string())),
    };

    // Alice sends blinded message to Bob
    let blind_signature: BlindSignature = match mint.mint_or_swap_tokens(blinded_message) {
      Ok(value) => value,
      Err(e) => return Err(WalletError::CouldNotMintToken(e.to_string())),
    };

    // Unblinds signature
    let c = match self.unblind(&mint, blind_signature, blinding_factor) {
      Ok(value) => value,
      Err(e) => return Err(WalletError::UnblindError(e.to_string())),
    };

    // Alice can take the pair (x, C) as a token and can send it to Carol.
    let token = (x, c);

    // verification
    let is_verified = match mint.verification(token.0.to_vec(), token.1) {
      Ok(value) => value,
      Err(e) => return Err(WalletError::CouldNotVerifyToken(e.to_string())),
    };

    println!("{}", is_verified);
    Ok(())
  }

  pub fn blind(&self, x: Vec<u8>, blinding_factor: SecretKey) -> Result<BlindedMessage> {
    // Computes Y = hash_to_curve(x)
    let y = hash_to_curve(x.to_vec());

    let secp = Secp256k1::new();
    let blinding_factor_scalar = Scalar::from(blinding_factor);
    // calculate `B_ = Y * rG`. `rG` also know as `g^r` (`g^b` in lucre's document https://github.com/benlaurie/lucre/blob/master/html/theory2.pdf)
    let b_ = match y.add_exp_tweak(&secp, &blinding_factor_scalar) {
      // y + rG
      Ok(value) => value,
      Err(e) => {
        return Err(WalletError::InvalidECMath(format!(
          "[mul_tweak|blind] {}",
          e
        )))
      }
    };

    Ok(BlindedMessage {
      amount: 10,
      b: b_,
      id: hex::encode(x),
    })
  }

  pub fn unblind(
    &self,
    mint: &Mint,
    blind_signature: BlindSignature,
    blinding_factor: SecretKey,
  ) -> Result<PublicKey> {
    // Alice can calculate the unblinded key as C_ - rK = kY + krG - krG = kY = C (unblinding)
    let secp = Secp256k1::new();
    // calculate scalar of blinding_factor
    let blinding_factor_scalar = Scalar::from(blinding_factor);
    // calculate rK
    let rk = match mint.pubkey.mul_tweak(&secp, &blinding_factor_scalar) {
      Ok(value) => value,
      Err(e) => {
        return Err(WalletError::InvalidECMath(format!(
          "[mul_tweak|unblind] {}",
          e
        )))
      }
    };

    // calculate C = C_ - rK
    match blind_signature.c.combine(&rk.negate(&secp)) {
      Ok(value) => Ok(value),
      Err(e) => Err(WalletError::InvalidECMath(format!(
        "[combine_negate|unblind] {}",
        e
      ))),
    }
  }
}
