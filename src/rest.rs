use serde::{Deserialize, Serialize};

use crate::{
  keyset::{Keyset, KeysetWithKeys},
  types::{Amount, BlindSignatures, BlindedMessages},
};

pub struct GetKeysResponse {
  pub keysets: Vec<KeysetWithKeys>,
}

pub struct GetKeysetsResponse {
  pub keysets: Vec<Keyset>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostMintQuoteBolt11Response {
  /// The quote ID,
  /// which is a random and unique id generated by the mint
  /// to internally look up the payment state.
  /// It MUST remain a secret between user and mint and
  /// MUST NOT be derivable from the payment request.
  /// A 3rd party who knows the quote ID can front-run and steal
  /// the tokens that this operation mints.
  pub quote: String,
  /// Payment request to fulfill
  pub request: String,
  /// Whether the request has been paid
  pub paid: bool,
  /// Unix timestamp (seconds) until which the mint quote is valid
  pub expiry: i64,
  /// the amount of the invoice
  pub amount: Amount,
}

impl PostMintQuoteBolt11Response {
  pub fn new(quote: String, request: String, paid: bool, expiry: i64, amount: Amount) -> Self {
    Self {
      quote,
      request,
      paid,
      expiry,
      amount,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostMintBolt11Request {
  pub quote_id: String,
  pub outputs: BlindedMessages
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostMintBolt11Response {
  pub signatures: BlindSignatures
}