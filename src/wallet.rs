use std::result;

use crate::{
  database::{CashuDatabase, DBType},
  helpers::{generate_key_pair, hash_to_curve},
  keyset::KeysetWithKeys,
  mint::Mint,
  rest::{
    PostMeltBolt11Request, PostMeltQuoteBolt11Request, PostMeltQuoteBolt11Response,
    PostMintBolt11Request, PostMintQuoteBolt11Response,
  },
  types::{
    Amount, BlindSignature, BlindSignatures, BlindedMessage, BlindedMessages, PaymentMethod, Proof,
    Proofs, Unit,
  },
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
  #[error("Could not meltt token: `{0}`")]
  CouldNotMeltToken(String),
  #[error("Could not verify token: `{0}`")]
  CouldNotVerifyToken(String),
  #[error("Could not mint quote: `{0}`")]
  CouldNotMintQuote(String),
  #[error("Could not check mint quote: `{0}`")]
  CouldNotCheckMintQuote(String),
  #[error("Method not allowed: `{0}`")]
  MethodNotAllowed(String),
}

type Result<T> = result::Result<T, WalletError>;

struct ValidAndInvalidProofs {
  valid_proofs: Proofs,
  invalid_proofs: Proofs,
}

pub struct Wallet {
  mint_url: String,
  mint: Mint,
  mint_valid_keysets: Vec<KeysetWithKeys>,
  db: CashuDatabase,
}

impl Wallet {
  pub fn new() -> Self {
    let wallet_db = CashuDatabase::new(DBType::WALLET).unwrap();
    let mint = Mint::new();
    let mint_url = "http://my_mint_url.cashu".to_string();

    // Get all (active) keysets from mint
    let mint_valid_keysets = mint.get_v1_keys().keysets;

    Self {
      mint_url,
      mint,
      mint_valid_keysets,
      db: wallet_db,
    }
  }

  pub fn new_testing_wallet(db_name: &str) -> Self {
    let wallet_db = CashuDatabase::new_testing_db(db_name).unwrap();
    let mint = Mint::new();
    let mint_url = "http://my_mint_url.cashu".to_string();

    // Get all (active) keysets from mint
    let mint_valid_keysets = mint.get_v1_keys().keysets;

    Self {
      mint_url,
      mint,
      mint_valid_keysets,
      db: wallet_db,
    }
  }

  pub fn mint_paid_quote(&mut self, quote_id: String) -> Result<()> {
    // get amount for this quote_id
    let quotes = self.db.get_all_wallet_quotes().unwrap();
    let amount = match quotes.iter().find(|(id, _)| *id == quote_id) {
      Some((_, amount)) => amount,
      None => {
        return Err(WalletError::CouldNotMintToken(
          "Quote with this ID not found".to_string(),
        ))
      }
    };
    let (amounts_in_powers_of_two, sat_keyset, mint_sat_keys) =
      self.get_mint_keys_and_divisible_amounts_from_amount(*amount);

    let method = PaymentMethod::BOLT11;
    let mut outputs: BlindedMessages = vec![];

    // Picks secret x (utf-8 encoded 32 bytes encoded string) -- coin ID
    let (x, _) = generate_key_pair();
    let x_vec: [u8; 32] = x.secret_bytes();

    // Get r, the blinding factor. r \in [0, (p-1)/2) <- part of the curve
    let (blinding_factor, _) = generate_key_pair();

    for amount_power_of_two in amounts_in_powers_of_two {
      let blinded_message = match self.blind(
        x_vec.to_vec(),
        blinding_factor,
        amount_power_of_two,
        sat_keyset.id.clone(),
      ) {
        Ok(value) => value,
        Err(e) => return Err(WalletError::BlindError(e.to_string())),
      };

      outputs.push(blinded_message);
    }

    let post_mint_bolt11_request = PostMintBolt11Request { quote_id, outputs };

    let blind_signatures = match self.mint.mint(method, post_mint_bolt11_request) {
      Ok(response) => response.signatures,
      Err(err) => return Err(WalletError::CouldNotMintToken(err.to_string())),
    };

    let new_proofs = self.build_proofs_from_promises(
      blind_signatures,
      mint_sat_keys,
      blinding_factor,
      x_vec.to_vec(),
    )?;

    // Save new proofs in the database
    let mut proofs_in_db = self.get_proofs_from_db();
    proofs_in_db.extend_from_slice(&new_proofs);
    self.save_new_proofs_to_db(proofs_in_db);

    Ok(())
  }

  // TODO: unit test
  pub fn melt_paid_quote(&mut self, quote_id: String) -> Result<()> {
    // get amount for this quote_id
    let quotes = self.db.get_all_wallet_quotes().unwrap();
    let amount = match quotes.iter().find(|(id, _)| *id == quote_id) {
      Some((_, amount)) => amount,
      None => {
        return Err(WalletError::CouldNotMeltToken(
          "Quote with this ID not found".to_string(),
        ))
      }
    };

    let proofs: Proofs = self.get_proofs_from_db();

    let mut inputs: Proofs = vec![];
    let mut total_amount_count = 0;
    for proof in &proofs {
      inputs.push(proof.clone());
      total_amount_count += proof.clone().amount;

      if total_amount_count >= *amount {
        break;
      }
    }

    let post_melt_bolt11_request = PostMeltBolt11Request {
      quote: quote_id,
      inputs: inputs.clone(),
    };

    let response = match self.mint.melt(post_melt_bolt11_request) {
      Ok(response) => response,
      Err(err) => return Err(WalletError::CouldNotMeltToken(err.to_string())),
    };

    // If paid is true, delete used inputs
    if response.paid {
      let proofs_without_used_inputs: Proofs = proofs
        .iter()
        .filter(|proof| !inputs.contains(proof))
        .map(|proof| proof.to_owned())
        .collect();

      self.save_new_proofs_to_db(proofs_without_used_inputs);
    }

    Ok(())
  }

  pub fn swap_tokens(&mut self, amounts: Vec<Amount>) -> Result<()> {
    let amounts_sum = amounts.iter().sum();

    let (_, sat_keyset, mint_sat_keys) =
      self.get_mint_keys_and_divisible_amounts_from_amount(amounts_sum);

    // Picks secret x (utf-8 encoded 32 bytes encoded string) -- coin ID
    let (x, _) = generate_key_pair();
    let x_vec: [u8; 32] = x.secret_bytes();

    // Get r, the blinding factor. r \in [0, (p-1)/2) <- part of the curve
    let (blinding_factor, _) = generate_key_pair();

    // Build the outputs based on the Vec<Amounts>
    let mut outputs: BlindedMessages = vec![];
    for amount in amounts {
      let blinded_message = match self.blind(
        x_vec.to_vec(),
        blinding_factor,
        amount,
        sat_keyset.id.clone(),
      ) {
        Ok(value) => value,
        Err(e) => return Err(WalletError::BlindError(e.to_string())),
      };

      outputs.push(blinded_message);
    }

    // Get some inputs we're going to use
    let inputs = self.get_inputs_from_specific_amounts(amounts_sum);

    // Swaps inputs for blind_signatures
    let blind_signatures: BlindSignatures = match self.mint.swap_tokens(inputs.clone(), outputs) {
      Ok(value) => value,
      Err(e) => return Err(WalletError::CouldNotMintToken(e.to_string())),
    };

    let new_proofs = self.build_proofs_from_promises(
      blind_signatures,
      mint_sat_keys,
      blinding_factor,
      x_vec.to_vec(),
    )?;

    // Remove used proofs from database
    let proofs_in_db = self.get_proofs_from_db();
    let mut proofs_updated: Proofs = vec![];
    for proof in proofs_in_db {
      if !inputs.contains(&proof) {
        proofs_updated.push(proof);
      }
    }

    // extend the proofs in db that weren't swapped with the new minted proofs
    proofs_updated.extend_from_slice(&new_proofs);

    // Save new proofs in the database
    self.save_new_proofs_to_db(proofs_updated);

    Ok(())
  }

  pub fn mint_quote(
    &mut self,
    method: PaymentMethod,
    amount: Amount,
    unit: Unit,
  ) -> Result<PostMintQuoteBolt11Response> {
    let mut mint = Mint::new();

    let mint_quote_response = match mint.mint_quote(method, amount, unit) {
      Ok(mint_quote) => mint_quote,
      Err(e) => return Err(WalletError::CouldNotMintQuote(e.to_string())),
    };

    // save quote to db
    self.save_quote_to_db(mint_quote_response.clone().quote, amount);

    Ok(mint_quote_response)
  }

  // TODO: unit test
  pub fn melt_quote(
    &mut self,
    method: PaymentMethod,
    request: String,
    unit: Unit,
  ) -> Result<PostMeltQuoteBolt11Response> {
    let mut mint = Mint::new();

    if method != PaymentMethod::BOLT11 {
      return Err(WalletError::MethodNotAllowed(format!("{:?}", method)));
    }

    let req = PostMeltQuoteBolt11Request { request, unit };

    let melt_quote_response = match mint.melt_quote(req) {
      Ok(melt_quote) => melt_quote,
      Err(e) => return Err(WalletError::CouldNotMintQuote(e.to_string())),
    };

    // save quote to db
    let total_amount = melt_quote_response.clone().amount + melt_quote_response.clone().fee_reserve;
    self.save_quote_to_db(melt_quote_response.clone().quote, total_amount);

    Ok(melt_quote_response)
  }

  fn get_valid_and_invalid_proofs(&self) -> ValidAndInvalidProofs {
    let mint_valid_keyset_ids = self
      .mint_valid_keysets
      .iter()
      .map(|keyset| keyset.id.clone())
      .collect::<Vec<String>>();
    let all_proofs_from_mint = self
      .db
      .get_all_proofs_from_mint(self.mint_url.clone())
      .unwrap();

    let mut proofs_with_valid_keyset_ids: Proofs = vec![];
    let mut proofs_with_invalid_keyset_ids: Proofs = vec![];

    for proof in all_proofs_from_mint {
      if mint_valid_keyset_ids.contains(&proof.id) {
        proofs_with_valid_keyset_ids.push(proof);
      } else {
        proofs_with_invalid_keyset_ids.push(proof);
      }
    }

    ValidAndInvalidProofs {
      valid_proofs: proofs_with_valid_keyset_ids,
      invalid_proofs: proofs_with_invalid_keyset_ids,
    }
  }

  fn get_proofs_from_db(&mut self) -> Proofs {
    self
      .db
      .get_all_proofs_from_mint(self.mint_url.clone())
      .unwrap()
  }

  fn save_new_proofs_to_db(&mut self, new_proofs: Proofs) {
    self
      .db
      .write_to_wallet_proofs_table(&self.mint_url, new_proofs)
      .unwrap();
  }

  fn save_quote_to_db(&mut self, quote_id: String, amount: Amount) {
    self
      .db
      .write_to_wallet_quotes_table(quote_id, amount)
      .unwrap();
  }

  fn get_inputs_from_specific_amounts(&self, amounts_sum: Amount) -> Proofs {
    let mut inputs: Proofs = vec![];
    let mut current_amount = 0;

    let proofs = self.get_valid_and_invalid_proofs();

    // Wallets SHOULD spend Proofs of inactive keysets first
    for proof in proofs.invalid_proofs {
      inputs.push(proof.clone());
      current_amount += proof.amount;

      // If I already have what I need, break
      if current_amount >= amounts_sum {
        break;
      }
    }

    if current_amount >= amounts_sum {
      return inputs;
    }

    for proof in proofs.valid_proofs {
      inputs.push(proof.clone());
      current_amount += proof.amount;

      // If I already have what I need, break
      if current_amount >= amounts_sum {
        break;
      }
    }

    inputs
  }

  fn get_mint_keys_and_divisible_amounts_from_amount(
    &self,
    amount: u64,
  ) -> (
    Vec<u64>,
    KeysetWithKeys,
    std::collections::BTreeMap<u64, PublicKey>,
  ) {
    let amounts_in_powers_of_two = self.express_amount_in_binary_form(amount);

    let sat_keyset = self
      .mint_valid_keysets
      .iter()
      .find(|keyset| keyset.unit == Unit::SAT)
      .unwrap();

    let mint_sat_keys = &sat_keyset.keys;
    (
      amounts_in_powers_of_two,
      sat_keyset.clone(),
      mint_sat_keys.clone(),
    )
  }

  fn build_proofs_from_promises(
    &self,
    blind_signatures: BlindSignatures,
    mint_sat_keys: std::collections::BTreeMap<u64, PublicKey>,
    blinding_factor: SecretKey,
    x_vec: Vec<u8>,
  ) -> Result<Proofs> {
    // Upon receiving the BlindSignatures from the mint Bob, the wallet of Alice unblinds them to generate Proofs
    // The wallet then stores these Proofs in its database.
    let mut new_proofs: Proofs = vec![];
    for blind_signature in blind_signatures.iter() {
      // get mint pubkey for this amount
      let pubkey = mint_sat_keys.get(&blind_signature.amount).unwrap();

      // Unblinds signature
      let c = match self.unblind(*pubkey, blind_signature.clone(), blinding_factor) {
        Ok(value) => value,
        Err(e) => return Err(WalletError::UnblindError(e.to_string())),
      };

      let proof = Proof {
        c,
        amount: blind_signature.amount,
        id: blind_signature.id.clone(),
        secret: hex::encode(x_vec.clone()),
      };

      new_proofs.push(proof)
    }

    Ok(new_proofs)
  }

  // Computes `B_ = Y + rG`, with r being a random blinding factor (blinding)
  fn blind(
    &self,
    x: Vec<u8>,
    blinding_factor: SecretKey,
    amount: Amount,
    keyset_id: String,
  ) -> Result<BlindedMessage> {
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
      amount,
      b: b_,
      id: keyset_id,
    })
  }

  fn unblind(
    &self,
    pubkey: PublicKey,
    blind_signature: BlindSignature,
    blinding_factor: SecretKey,
  ) -> Result<PublicKey> {
    // Alice can calculate the unblinded key as C_ - rK = kY + krG - krG = kY = C (unblinding)
    let secp = Secp256k1::new();
    // calculate scalar of blinding_factor
    let blinding_factor_scalar = Scalar::from(blinding_factor);
    // calculate rK
    let rk = match pubkey.mul_tweak(&secp, &blinding_factor_scalar) {
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

  fn express_amount_in_binary_form(&self, amount: Amount) -> Vec<Amount> {
    let binary = format!("{:b}", amount);

    let base: u64 = 2;
    let mut amounts: Vec<Amount> = vec![];
    for (idx, value) in binary.chars().rev().enumerate() {
      if value == '1' {
        amounts.push(base.pow(idx.try_into().unwrap()));
      }
    }

    amounts
  }
}

#[cfg(test)]
mod tests {
  use std::{fs, str::FromStr};

  use bitcoin::secp256k1::PublicKey;

  use crate::types::{Amount, Proof, Proofs};

  use super::Wallet;

  struct Sut {
    wallet: Wallet,
    db_name: String,
  }

  impl Drop for Sut {
    fn drop(&mut self) {
      self.remove_temp_db();
    }
  }

  impl Sut {
    fn new(db_name: &str, valid_proofs: Proofs, invalid_proofs: Proofs) -> Self {
      let mut wallet = Wallet::new_testing_wallet(db_name);

      let mut proofs = valid_proofs;
      proofs.extend_from_slice(&invalid_proofs);
      let _ = wallet
        .db
        .write_to_wallet_proofs_table(&wallet.mint_url, proofs);

      Self {
        wallet,
        db_name: db_name.to_string(),
      }
    }

    fn remove_temp_db(&self) {
      fs::remove_file(format!("db/test/{}.redb", self.db_name)).unwrap();
    }

    fn gen_inputs_from_amount(amounts_binary_form: Vec<Amount>) -> Proofs {
      let mut proofs: Proofs = vec![];
      let pubkey =
        PublicKey::from_str("02ec4a46e8d58aa75f03dc40a6ba58330fcb7d2c15ef99f901eca18d9d3bc6ec4e")
          .unwrap();

      let secret = "407218161f9f183768fcd1904b3180a89f9680ea5fd72f69a6ac7ef334aea2b3".to_string();

      for amount in amounts_binary_form {
        let proof = Proof {
          amount,
          c: pubkey,
          id: "randomid".to_string(),
          secret: secret.clone(),
        };
        proofs.push(proof);
      }

      proofs
    }
  }

  #[test]
  fn get_inputs_from_specific_amounts() {
    // arrange
    let inputs_amounts: Vec<Amount> = vec![2, 8, 16, 32, 64]; // 122
    let inputs = Sut::gen_inputs_from_amount(inputs_amounts.clone());
    let sut = Sut::new("get_inputs_from_specific_amounts", inputs, vec![]);
    let required_amount_to_swap_sum: Amount = 63; // [1, 2, 4, 8, 16, 32]

    let response_inputs = sut
      .wallet
      .get_inputs_from_specific_amounts(required_amount_to_swap_sum);

    let response_total_amounts: Amount = response_inputs.iter().map(|proof| proof.amount).sum();

    assert!(response_total_amounts >= required_amount_to_swap_sum);
  }
}
