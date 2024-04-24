use std::{collections::BTreeMap, str::FromStr};

use bitcoin::secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Deserializer, Serialize};
use strum::EnumString;

pub type Amount = u64;

/// A [`Proof`] is also called an `input` and is generated by Alice (wallet) from a [`BlindSignature`] it received.
/// An array [`Proof``] is called Proofs
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Token {
  /// the mint URL
  pub mint: String,
  /// proofs of the token
  pub proofs: Proofs,
}

pub type Tokens = Vec<Token>;

/// An encrypted ("blinded") secret and an amount is sent from Alice (wallet) to Bob (mint) for minting tokens or for swapping tokens.
/// A [`BlindedMessage`] is also called an `output`.
#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct BlindSignature {
  /// value of the blinded token
  pub amount: Amount,
  /// keyset id (hex) of the mint keys that signed the token
  pub id: String,
  /// blinded signature on the secret message `B_` sent by [`BlindedMessage`]
  #[serde(rename = "C_")]
  pub c: PublicKey,
}

pub type BlindSignatures = Vec<BlindSignature>;

pub type Keys = BTreeMap<Amount, PublicKey>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Keypair {
  pub pubkey: PublicKey,
  pub secretkey: SecretKey
}

pub type Keypairs = Vec<Keypair>;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Serialize, Clone, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Unit {
  BTC,
  SAT,
}

impl<'de> Deserialize<'de> for Unit {
  fn deserialize<D>(deserializer: D) -> Result<Unit, D::Error>
  where
      D: Deserializer<'de>,
  {
      let s: String = Deserialize::deserialize(deserializer)?;
      Unit::from_str(&s.to_lowercase()).map_err(serde::de::Error::custom)
  }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Serialize, Clone, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum PaymentMethod {
  BOLT11,
}

impl<'de> Deserialize<'de> for PaymentMethod {
  fn deserialize<D>(deserializer: D) -> Result<PaymentMethod, D::Error>
  where
      D: Deserializer<'de>,
  {
      let s: String = Deserialize::deserialize(deserializer)?;
      PaymentMethod::from_str(&s.to_lowercase()).map_err(serde::de::Error::custom)
  }
}