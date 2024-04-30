use std::result;

use crate::{
  database::{CashuDatabase, DBType},
  helpers::{generate_key_pair, hash_to_curve},
  keyset::KeysetWithKeys,
  mint::Mint,
  rest::{PostMintBolt11Request, PostMintQuoteBolt11Response},
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
  #[error("Could not verify token: `{0}`")]
  CouldNotVerifyToken(String),
  #[error("Could not mint quote: `{0}`")]
  CouldNotMintQuote(String),
  #[error("Could not check mint quote: `{0}`")]
  CouldNotCheckMintQuote(String),
}

type Result<T> = result::Result<T, WalletError>;

pub struct Wallet {
  valid_proofs: Proofs,
  invalid_proofs: Proofs,
  quotes: Vec<(String, Amount)>,
  url: String,
  mint: Mint,
  mint_keysets: Vec<KeysetWithKeys>,
}

impl Wallet {
  pub fn new() -> Self {
    let wallet_db = CashuDatabase::new(DBType::WALLET).unwrap();
    let mint = Mint::new();
    let mint_url = "http://my_mint_url.cashu".to_string();

    // Get all (active) keysets from mint
    let mint_keysets = mint.get_v1_keys().keysets;
    let mint_keyset_ids = mint_keysets
      .iter()
      .map(|keyset| keyset.id.clone())
      .collect::<Vec<String>>();
    let all_proofs_from_mint = wallet_db
      .get_all_proofs_from_mint(mint_url.clone())
      .unwrap();

    let mut proofs_with_valid_keyset_ids: Proofs = vec![];
    // This invalid proofs can be used to request swap of tokens (so we update their keyset_id)
    let mut proofs_with_invalid_keyset_ids: Proofs = vec![];

    for proof in all_proofs_from_mint {
      if mint_keyset_ids.contains(&proof.id) {
        proofs_with_valid_keyset_ids.push(proof);
      } else {
        proofs_with_invalid_keyset_ids.push(proof);
      }
    }

    let quotes = wallet_db.get_all_wallet_quotes().unwrap();
    Self {
      valid_proofs: proofs_with_valid_keyset_ids,
      invalid_proofs: proofs_with_invalid_keyset_ids,
      quotes,
      url: mint_url,
      mint,
      mint_keysets,
    }
  }

  pub fn mint_paid_quote(&self, quote_id: String) -> Result<()> {
    // get amount for this quote_id
    let amount = match self.quotes.iter().find(|(id, _)| *id == quote_id) {
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
        secret: hex::encode(x_vec),
      };

      new_proofs.push(proof)
    }

    // TODO: save proofs in database

    Ok(())
  }

  // TODO: Wallets SHOULD store keysets the first time they encounter them along with the URL of the mint they are from.
  // TODO: Wallets SHOULD spend Proofs of inactive keysets first
  // TODO: When constructing outputs for an operation, wallets MUST choose only active keysets
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
    // TODO: get all the inputs that the total amount will
    // match exactly what we need...
    let mut inputs: Proofs = vec![];
    let mut current_amount = 0;
    for proof in &self.valid_proofs {
      inputs.push(proof.clone());
      current_amount += proof.amount;
      // If I already have what I need, break
      if current_amount == amounts_sum {
        break;
      }
    }

    // Swaps inputs for blind_signatures
    let blind_signatures: BlindSignatures =
      match self.mint.swap_tokens(inputs, outputs) {
        Ok(value) => value,
        Err(e) => return Err(WalletError::CouldNotMintToken(e.to_string())),
      };

    let mut new_proofs: Proofs = vec![];
    for (idx, blind_signature) in blind_signatures.iter().enumerate() {
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
        secret: self.valid_proofs.clone()[idx].secret.clone(), // TODO: not sure
      };

      new_proofs.push(proof)
    }

    // TODO: save proofs in database
    Ok(())
  }

  // TODO: The wallet MUST store the `amount` in the request and
  // TODO: the `quote id` in the response in its database so it can later request the tokens after paying the request.
  pub fn mint_quote(
    &self,
    method: PaymentMethod,
    amount: Amount,
    unit: Unit,
  ) -> Result<PostMintQuoteBolt11Response> {
    let mut mint = Mint::new();

    match mint.mint_quote(method, amount, unit) {
      Ok(mint_quote) => Ok(mint_quote),
      Err(e) => Err(WalletError::CouldNotMintQuote(e.to_string())),
    }
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
      .mint_keysets
      .iter()
      .find(|keyset| keyset.unit == Unit::SAT)
      .unwrap();

    let mint_sat_keys = &sat_keyset.keys;
    (amounts_in_powers_of_two, sat_keyset.clone(), mint_sat_keys.clone())
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
