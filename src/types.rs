use std::collections::BTreeMap;

use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

pub type Amount = u64;

/// A [`Proof`] is also called an `input` and is generated by Alice (wallet) from a [`BlindSignature`] it received.
/// An array [`Proof``] is called Proofs
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof {
  /// amount of the [`Proof`]
  pub amount: Amount,
  /// keyset id of the mint public keys that signed the token (hex string)
  pub id: String,
  /// utf-8 encoded string (it is the `x`)
  pub secret: String,
  /// unblinded signature on `secret`
  #[serde(rename = "C")]
  pub c: PublicKey,
}

pub type Proofs = Vec<Proof>;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Token {
  /// the mint URL
  pub mint: String,
  /// proofs of the token
  pub proofs: Proofs,
}

/// An encrypted ("blinded") secret and an amount is sent from Alice (wallet) to Bob (mint) for minting tokens or for swapping tokens.
/// A [`BlindedMessage`] is also called an `output`.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlindedMessage {
  /// the value for the requested [`BlindSignature`]
  pub amount: Amount,
  /// requested keyset ID (hex) from which we expect a signature
  pub id: String,
  /// blinded secret message generated by Alice (wallet)
  #[serde(rename = "B_")]
  pub b: PublicKey,
}

pub type BlindedMessages = Vec<BlindedMessage>;

/// A [`BlindSignature`] is sent from Bob (mint) to Alice (wallet) after minting tokens or after swapping tokens.
/// A [`BlindSignature`] is also called a `promise`.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlindSignature {
  /// value of the blinded token
  pub amount: Amount,
  /// keyset id (hex) of the mint keys that signed the token
  pub id: String,
  /// blinded signature on the secret message `B_` sent by [`BlindedMessage`]
  #[serde(rename = "C_")]
  pub c: PublicKey,
}

pub type Keys = BTreeMap<Amount, PublicKey>;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, strum::Display, Serialize, Deserialize, Clone)]
pub enum Unit {
  BTC,
  SAT,
}
