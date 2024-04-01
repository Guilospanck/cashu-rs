use serde::{Deserialize, Serialize};

use crate::{helpers::{generate_key_pair, hash_to_curve}, mint::Mint, types::{BlindSignature, BlindedMessage}};

use bitcoin::{
  key::Secp256k1,
  secp256k1::{PublicKey, SecretKey, Scalar},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {}

impl Wallet {
  pub fn new() -> Self {
    Self {}
  }

  pub fn begin(&self) {
    // Mint Bob publishes public key K = kG
    let mint = Mint::new();

    // Picks secret x (utf-8 encoded 32 bytes encoded string) -- coin ID
    let (x, _) = generate_key_pair();
    let x = x.secret_bytes();

    // Get r, the blinding factor. r \in [0, (p-1)/2) <- part of the curve
    let (blinding_factor, _) = generate_key_pair();

    // Computes `B_ = Y + rG`, with r being a random blinding factor (blinding)
    let blinded_message = self.blind(x.to_vec(), blinding_factor);

    // Alice sends blinded message to Bob
    let blind_signature: BlindSignature;
    match mint.mint_or_swap_tokens(blinded_message) {
      Ok(value) => blind_signature = value,
      Err(e) => return eprintln!("Could not mint token: {e}"),
    }

    // Unblinds signature
    let c = self.unblind(&mint, blind_signature, blinding_factor);

    // Alice can take the pair (x, C) as a token and can send it to Carol.
    let token = (x, c);

    // verification
    let is_verified = mint.verification(token.0.to_vec(), token.1);
    println!("{}", is_verified);
  }

  pub fn blind(&self, x: Vec<u8>, blinding_factor: SecretKey) -> BlindedMessage {
    // Computes Y = hash_to_curve(x)
    let y = hash_to_curve(x.to_vec());

    let secp = Secp256k1::new();
    let blinding_factor_scalar = Scalar::from(blinding_factor);
    // calculate `B_ = Y * rG`. `rG` also know as `g^r` (`g^b` in lucre's document https://github.com/benlaurie/lucre/blob/master/html/theory2.pdf)
    let b_ = y
      .add_exp_tweak(&secp, &blinding_factor_scalar) // y + rG
      .expect("EC math could not add_exp_tweak");

    let blinded_message = BlindedMessage {
      amount: 10,
      b: b_,
      id: hex::encode(x),
    };

    blinded_message
  }

  pub fn unblind(
    &self,
    mint: &Mint,
    blind_signature: BlindSignature,
    blinding_factor: SecretKey,
  ) -> PublicKey {
    // Alice can calculate the unblinded key as C_ - rK = kY + krG - krG = kY = C (unblinding)
    let secp = Secp256k1::new();
    // calculate scalar of blinding_factor
    let blinding_factor_scalar = Scalar::from(blinding_factor);
    // calculate rK
    let rk = mint
      .pubkey
      .mul_tweak(&secp, &blinding_factor_scalar)
      .expect("EC math could not mul_tweak");
    // calculate C = C_ - rK
    let c = blind_signature
      .c
      .combine(&rk.negate(&secp))
      .expect("EC math combine math error");

    c
  }
}
