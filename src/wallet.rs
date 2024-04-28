use std::result;

use serde::{Deserialize, Serialize};

use crate::{
  database::{CashuDatabase, DBType},
  helpers::{generate_key_pair, hash_to_curve},
  mint::Mint,
  rest::{PostMintBolt11Request, PostMintQuoteBolt11Response},
  types::{
    Amount, BlindSignature, BlindSignatures, BlindedMessage, BlindedMessages, PaymentMethod, Proof,
    Proofs, Token, Tokens, Unit,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
  tokens: Tokens,
  quotes: Vec<(String, Amount)>,
  url: String,
}

// TODO: Wallets can request the list of keyset IDs from the mint upon startup
// TODO  and load only tokens from its database that have a keyset ID supported
// TODO  by the mint it interacts with. This also helps wallets to determine
// TODO  whether the mint has rotated to a new current keyset (i.e. added new
// TODO  active keysets and inactivated old ones) and whether the wallet should
// TODO  recycle all tokens from inactive keysets to currently active ones.
impl Wallet {
  pub fn new() -> Self {
    let wallet_db = CashuDatabase::new(DBType::WALLET).unwrap();
    let tokens = wallet_db.get_all_tokens().unwrap();
    let quotes = wallet_db.get_all_wallet_quotes().unwrap();
    let url = "http://my_mint_url.cashu".to_string();
    Self {
      tokens,
      quotes,
      url,
    }
  }

  pub fn mint_paid_quote(&self, quote_id: String) -> Result<()> {
    let mint = Mint::new();

    // Get r, the blinding factor. r \in [0, (p-1)/2) <- part of the curve
    let (blinding_factor, _) = generate_key_pair();

    // Get all proofs from this mint
    let proofs = self.get_proofs_from_mint(self.url.clone());

    // get amount for this quote_id
    // TODO: use amount to calculate/get the proofs
    let amount = match self.quotes.iter().find(|(id, _)| *id == quote_id) {
      Some((_, amount)) => amount,
      None => {
        return Err(WalletError::CouldNotMintToken(
          "Quote with this ID not found".to_string(),
        ))
      }
    };

    // Get all keysets
    let mint_keysets = mint.get_v1_keys();
    let sat_keyset = mint_keysets
      .keysets
      .iter()
      .find(|keyset| keyset.unit == Unit::SAT)
      .unwrap();
    
    // TODO: check if the amount we have is allowed for the mint and, if not,
    // TODO: check if can be divisible (by 2).
    // Example: if we want 63 sats and the mint only allows 1, 2, 4, 8, 16, it could be
    // done with 3*16 (48) + 1*8 (8) + 1*4 (4) + 1*2 (2) + 1*1 (1) = 63
    let mint_sat_keys = &sat_keyset.keys;

    let method = PaymentMethod::BOLT11;
    let mut outputs: BlindedMessages = vec![];

    // If we don't have any proofs, usually it means that we are
    // connecting to this mint for the first time.
    if proofs.is_empty() {
      // Picks secret x (utf-8 encoded 32 bytes encoded string) -- coin ID
      let (x, _) = generate_key_pair();
      let x_vec = x.secret_bytes();


      // TODO: here it looks like we can change the amount, so we request different specific amounts (but maintaining the
      // TODO: same total amount)
      let blinded_message = match self.blind(x_vec.to_vec(), blinding_factor, *amount, sat_keyset.id.clone())
      {
        Ok(value) => value,
        Err(e) => return Err(WalletError::BlindError(e.to_string())),
      };

      outputs.push(blinded_message);
    } else {
      // TODO: select which proofs we want
      for proof in &proofs {
        let x_vec = hex::decode(proof.secret.clone()).unwrap();
        // TODO: here it looks like we can change the amount, so we request different specific amounts (but maintaining the
        // TODO: same total amount)
        let blinded_message =
          match self.blind(x_vec, blinding_factor, proof.amount, proof.id.clone()) {
            Ok(value) => value,
            Err(e) => return Err(WalletError::BlindError(e.to_string())),
          };

        outputs.push(blinded_message);
      }
    }

    let post_mint_bolt11_request = PostMintBolt11Request { quote_id, outputs };

    let blind_signatures = match mint.mint(method, post_mint_bolt11_request) {
      Ok(response) => response.signatures,
      Err(err) => return Err(WalletError::CouldNotMintToken(err.to_string()))
    };
    
    // Upon receiving the BlindSignatures from the mint Bob, the wallet of Alice unblinds them to generate Proofs
    // The wallet then stores these Proofs in its database.
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
        secret: proofs.clone()[idx].secret.clone(), // TODO: not sure
      };

      new_proofs.push(proof)
    }

    // TODO: save proofs in database

    Ok(())
  }

  // TODO: Wallets SHOULD store keysets the first time they encounter them along with the URL of the mint they are from.
  // TODO: Wallets SHOULD spend Proofs of inactive keysets first
  // TODO: When constructing outputs for an operation, wallets MUST choose only active keysets
  pub fn swap_tokens(&self) -> Result<()> {
    // Mint Bob publishes public key K = kG
    let mut mint = Mint::new();

    // Get all keysets
    let mint_keysets = mint.get_v1_keys();
    let sat_keyset = mint_keysets
      .keysets
      .iter()
      .find(|keyset| keyset.unit == Unit::SAT)
      .unwrap();
    let mint_sat_keys = &sat_keyset.keys;

    // Get all tokens (in wallet database) from this mint
    let tokens_from_mint = self
      .tokens
      .iter()
      .find(|Token { mint, .. }| *mint == self.url);

    // Get all proofs from this mint
    let mut proofs = vec![];
    if let Some(token) = tokens_from_mint {
      proofs = token.proofs.clone();
    }

    // Get r, the blinding factor. r \in [0, (p-1)/2) <- part of the curve
    let (blinding_factor, _) = generate_key_pair();

    let mut outputs: BlindedMessages = vec![];
    // TODO: select which proofs we want
    for proof in &proofs {
      let x_vec = hex::decode(proof.secret.clone()).unwrap();
      // Computes `B_ = Y + rG`, with r being a random blinding factor (blinding)
      // TODO: here it looks like we can change the amount, so we request different pocket change tokens from mint
      let blinded_message = match self.blind(x_vec, blinding_factor, proof.amount, proof.id.clone())
      {
        Ok(value) => value,
        Err(e) => return Err(WalletError::BlindError(e.to_string())),
      };

      outputs.push(blinded_message);
    }

    // Swaps inputs for blind_signatures
    let blind_signatures: BlindSignatures = match mint.swap_tokens(proofs.clone(), outputs) {
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
        secret: proofs.clone()[idx].secret.clone(), // TODO: not sure
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

  fn get_proofs_from_mint(&self, mint_url: String) -> Proofs {
    match self.tokens.iter().find(|token| token.mint == mint_url) {
      Some(token) => token.proofs.clone(),
      None => vec![],
    }
  }
}
