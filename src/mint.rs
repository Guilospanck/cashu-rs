use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use std::{collections::HashMap, result, str::FromStr};

use bitcoin::{
  key::Secp256k1,
  secp256k1::{Scalar, SecretKey},
};

use chrono::Utc;
use lightning_invoice::{self, Bolt11Invoice, Currency, InvoiceBuilder};
use std::time::Duration;
use uuid::Uuid;

use crate::{
  database::{CashuDatabase, DBType},
  helpers::hash_to_curve,
  keyset::{generate_keyset_and_keypairs, Keyset, KeysetWithKeys, Keysets},
  rest::{
    GetInfoResponse, GetKeysResponse, GetKeysetsResponse, Nut, NutMethod, NutSupported, NutValue,
    PostMeltBolt11Request, PostMeltBolt11Response, PostMeltQuoteBolt11Request,
    PostMeltQuoteBolt11Response, PostMintBolt11Request, PostMintBolt11Response,
    PostMintQuoteBolt11Response,
  },
  types::{
    Amount, BlindSignature, BlindSignatures, BlindedMessage, BlindedMessages, Keypairs,
    PaymentMethod, Proof, Proofs, Unit,
  },
};

/// [`Mint`] error
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum MintError {
  #[error("Invalid EC math: `{0}`")]
  InvalidECMath(String),
  #[error("Error verifying proof: `{0}`")]
  ErrorVerifyingProof(String),
  #[error("Invalid proof")]
  InvalidProof,
  #[error("Amounts don't match")]
  AmountsDoNotMatch,
  #[error("Insufficient funds")]
  InsufficientFunds,
  #[error("Payment method not supported")]
  PaymentMethodNotSupported,
  #[error("Could not create mint quote: `{0}`")]
  CouldNotCreateMintQuote(String),
  #[error("Mint quote not found: `{0}`")]
  MintQuoteNotFound(String),
  #[error("Melt quote not found: `{0}`")]
  MeltQuoteNotFound(String),
  #[error("Mint quote not paid")]
  MintQuoteNotPaid,
  #[error("Invalid invoice: `{0}`")]
  InvalidInvoice(String),
  #[error("Payment preimage not found")]
  PaymentPreimageNotFound,
}

type Result<T> = result::Result<T, MintError>;

pub struct Mint {
  keysets: Vec<KeysetWithKeys>,
  keypairs: Keypairs,
  db: CashuDatabase,
  private_key: SecretKey,
  // This is different for each payment
  // Think of it as an ID of the invoice
  payment_preimage: Option<Vec<u8>>,
}

impl Mint {
  pub fn new() -> Self {
    let mut db = CashuDatabase::new(DBType::MINT).unwrap();
    let mut keysets = db.get_all_keysets().unwrap();
    let mut keypairs = db.get_all_keypairs().unwrap();

    if keysets.is_empty() || keypairs.is_empty() {
      let (generated_keyset, generated_keypairs) = generate_keyset_and_keypairs();
      db.write_to_keysets_table(&generated_keyset.id, generated_keyset.clone())
        .unwrap();

      for keypair in generated_keypairs.clone() {
        db.write_to_keypairs_table(keypair.pubkey, keypair.secretkey)
          .unwrap();
      }

      keysets.push(generated_keyset);
      keypairs = generated_keypairs;
    }

    let private_key = SecretKey::from_slice(
      &[
        0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06,
        0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d,
        0xb7, 0x34,
      ][..],
    )
    .unwrap();

    Self {
      keysets,
      keypairs,
      db,
      private_key,
      payment_preimage: None,
    }
  }

  fn new_testing_mint(db_name: &str, keyset: KeysetWithKeys, keypairs: Keypairs) -> Self {
    let db = CashuDatabase::new_testing_db(db_name).unwrap();
    let keysets = vec![keyset];
    let private_key = SecretKey::from_slice(
      &[
        0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06,
        0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d,
        0xb7, 0x34,
      ][..],
    )
    .unwrap();

    Self {
      keysets,
      keypairs,
      db,
      private_key,
      payment_preimage: None,
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
  ///
  /// /v1/keys
  pub fn get_v1_keys(&self) -> GetKeysResponse {
    let active_keysets: Vec<KeysetWithKeys> = self
      .keysets
      .clone()
      .into_iter()
      .filter(|x| x.active)
      .collect();

    GetKeysResponse {
      keysets: active_keysets,
    }
  }

  /// /v1/keys/{keyset_id}
  pub fn get_v1_keys_keyset_id(&self, keyset_id: String) -> GetKeysResponse {
    let mut keysets_with_keys: Vec<KeysetWithKeys> = vec![];

    if let Some(keyset) = self
      .keysets
      .clone()
      .into_iter()
      .find(|KeysetWithKeys { id, .. }| *id == keyset_id)
    {
      keysets_with_keys.push(keyset)
    };

    GetKeysResponse {
      keysets: keysets_with_keys,
    }
  }

  /// /v1/keysets
  pub fn get_v1_keysets(&self) -> GetKeysetsResponse {
    let mut keysets: Keysets = vec![];
    self.keysets.clone().into_iter().for_each(
      |KeysetWithKeys {
         id, unit, active, ..
       }| keysets.push(Keyset { id, unit, active }),
    );

    GetKeysetsResponse { keysets }
  }

  pub fn info(&self) -> GetInfoResponse {
    let mut nuts: HashMap<String, NutValue> = HashMap::new();

    // NUT-04
    let methods_nut_04 = vec![NutMethod {
      method: PaymentMethod::BOLT11,
      unit: Unit::SAT,
      min_amount: 0,
      max_amount: 10000,
    }];
    let nut04 = Nut {
      methods: methods_nut_04,
      disabled: false,
    };

    // NUT-05
    let methods_nut_05 = vec![NutMethod {
      method: PaymentMethod::BOLT11,
      unit: Unit::SAT,
      min_amount: 100,
      max_amount: 10000,
    }];
    let nut05 = Nut {
      methods: methods_nut_05,
      disabled: false,
    };

    // NUT-07, 08, 09, 10, 12
    let not_supported = NutValue::Supported(NutSupported { supported: false });

    nuts.insert("4".to_owned(), NutValue::Nut(nut04));
    nuts.insert("5".to_owned(), NutValue::Nut(nut05));
    nuts.insert("7".to_owned(), not_supported.clone());
    nuts.insert("8".to_owned(), not_supported.clone());
    nuts.insert("9".to_owned(), not_supported.clone());
    nuts.insert("10".to_owned(), not_supported.clone());
    nuts.insert("12".to_owned(), not_supported);

    GetInfoResponse {
      name: "Guilospanck's mint".to_string(),
      pubkey: None,
      version: "cashu-rs/0.1.0".to_string(),
      description: "A mint".to_string(),
      description_long: "A mint but with more chars".to_string(),
      contact: vec![
        [
          "email".to_string(),
          "guilospanck@protonmail.com".to_string(),
        ],
        [
          "linkedin".to_string(),
          "https://www.linkedin.com/in/guilhermerpereira/".to_string(),
        ],
      ],
      motd: "Dwell on the beauty of life. Watch the stars and see yourself running with them"
        .to_string(),
      nuts,
    }
  }

  pub fn swap_tokens(
    &mut self,
    inputs: Proofs,
    outputs: BlindedMessages,
  ) -> Result<BlindSignatures> {
    // check if the amount of proofs is the same as the requested outputs
    let total_amount_inputs = inputs
      .iter()
      .map(|proof| proof.amount)
      .reduce(|acc, e| acc + e)
      .unwrap();
    let total_amount_outputs = outputs
      .iter()
      .map(|proof| proof.amount)
      .reduce(|acc, e| acc + e)
      .unwrap();
    if total_amount_inputs < total_amount_outputs {
      return Err(MintError::InsufficientFunds);
    }

    // verify inputs
    for input in inputs.clone() {
      // check if input is invalid
      match self.db.get_invalid_input(input.clone()) {
        Ok(res) => {
          if let Some(_invalid) = res {
            return Err(MintError::InvalidProof);
          }
        }
        Err(e) => return Err(MintError::ErrorVerifyingProof(e.to_string())),
      };

      match self.verify_input(input.clone()) {
        Ok(verified) => {
          if !verified {
            return Err(MintError::InvalidProof);
          }
        }
        Err(e) => return Err(MintError::ErrorVerifyingProof(e.to_string())),
      }
    }

    // invalidate inputs
    for input in inputs {
      let _ = self.db.write_to_invalid_inputs_table(input);
    }

    // mint outputs
    let mut promises: BlindSignatures = vec![];
    for output in outputs {
      let promise = self.mint_token(output)?;
      promises.push(promise);
    }

    Ok(promises)
  }

  pub fn mint_quote(
    &mut self,
    method: PaymentMethod,
    amount: Amount,
    _unit: Unit,
  ) -> Result<PostMintQuoteBolt11Response> {
    if method != PaymentMethod::BOLT11 {
      return Err(MintError::PaymentMethodNotSupported);
    }

    let quote: String = Uuid::new_v4().to_string();

    let payment_preimage = [0; 32].to_vec();
    self.payment_preimage = Some(payment_preimage.clone());
    let payment_hash = sha256::Hash::from_slice(&payment_preimage[..]).unwrap();

    // This changes for each hop (lightning node in the way
    // until the final node, which will also have a different
    // payment_secret)
    let payment_secret = lightning_invoice::PaymentSecret([42u8; 32]);

    // valid for 1h
    let invoice_expiry = Duration::from_secs(3600);

    let invoice = InvoiceBuilder::new(Currency::Bitcoin)
      .description("Invoice created".into())
      .payment_hash(payment_hash)
      .payment_secret(payment_secret)
      .current_timestamp()
      .min_final_cltv_expiry_delta(144)
      .amount_milli_satoshis(amount)
      .expiry_time(invoice_expiry)
      .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &self.private_key))
      .unwrap();

    let request = invoice.to_string();

    let paid = false;
    let expiry: i64 = Utc::now().timestamp() + 3600;

    let mint_quote = PostMintQuoteBolt11Response::new(quote, request, paid, expiry, amount);

    let _ = self
      .db
      .write_to_mint_quotes_table(mint_quote.clone())
      .map_err(|e| MintError::CouldNotCreateMintQuote(e.to_string()));

    Ok(mint_quote)
  }

  pub fn melt_quote(
    &mut self,
    PostMeltQuoteBolt11Request { request, unit: _ }: PostMeltQuoteBolt11Request,
  ) -> Result<PostMeltQuoteBolt11Response> {
    let quote: String = Uuid::new_v4().to_string();

    let bolt11_invoice = Bolt11Invoice::from_str(&request)
      .map_err(|err| MintError::InvalidInvoice(err.to_string()))?;
    let amount: Amount = bolt11_invoice.amount_milli_satoshis().unwrap() * 1000; // in sats
    let fee_reserve: Amount = 0;
    let expiry: i64 = bolt11_invoice.expiry_time().as_secs() as i64;
    let paid = false;

    let response = PostMeltQuoteBolt11Response {
      quote,
      amount,
      fee_reserve,
      paid,
      expiry,
    };

    self
      .db
      .write_to_melt_quotes_table(response.clone())
      .unwrap();

    Ok(response)
  }

  pub fn melt(
    &self,
    PostMeltBolt11Request { quote, inputs }: PostMeltBolt11Request,
  ) -> Result<PostMeltBolt11Response> {
    // Get quote info from database
    let quote_info = match self.db.get_melt_quote(quote) {
      Ok(res) => {
        if res.is_none() {
          return Err(MintError::MeltQuoteNotFound("".to_string()));
        }

        res.unwrap()
      }
      Err(e) => return Err(MintError::MeltQuoteNotFound(e.to_string())),
    };

    // Check if inputs have the necessary amount to pay the invoice
    let amount_needed = quote_info.amount + quote_info.fee_reserve;
    let total_amount_of_inputs: Amount = inputs.iter().map(|proof| proof.amount).sum();
    if total_amount_of_inputs < amount_needed {
      return Err(MintError::InsufficientFunds);
    }

    let paid = true;

    let payment_preimage = match self.payment_preimage.clone() {
      Some(preimage) => preimage,
      None => return Err(MintError::PaymentPreimageNotFound),
    };

    let payment_preimage = hex::encode(payment_preimage);

    let response = PostMeltBolt11Response {
      paid,
      payment_preimage: Some(payment_preimage),
    };

    Ok(response)
  }

  pub fn check_mint_quote_state(&self, quote_id: String) -> Result<PostMintQuoteBolt11Response> {
    match self.db.get_mint_quote(quote_id) {
      Ok(res) => {
        if res.is_none() {
          return Err(MintError::MintQuoteNotFound("".to_string()));
        }

        Ok(res.unwrap())
      }
      Err(e) => Err(MintError::MintQuoteNotFound(e.to_string())),
    }
  }

  // TODO: unit tests
  pub fn check_melt_quote_state(&self, quote_id: String) -> Result<PostMeltQuoteBolt11Response> {
    match self.db.get_melt_quote(quote_id) {
      Ok(res) => {
        if res.is_none() {
          return Err(MintError::MeltQuoteNotFound("".to_string()));
        }

        Ok(res.unwrap())
      }
      Err(e) => Err(MintError::MeltQuoteNotFound(e.to_string())),
    }
  }

  pub fn mint(
    &self,
    method: PaymentMethod,
    PostMintBolt11Request { quote_id, outputs }: PostMintBolt11Request,
  ) -> Result<PostMintBolt11Response> {
    let mint_quote = self.check_mint_quote_state(quote_id)?;

    // check if mint_quote is paid
    if !mint_quote.paid {
      return Err(MintError::MintQuoteNotPaid);
    }

    // check if method is allowed
    if method != PaymentMethod::BOLT11 {
      return Err(MintError::PaymentMethodNotSupported);
    }

    // check if blinded messages amounts equal to amounts in the mint_quote from quote_id
    let outputs_amount: Amount = outputs.iter().map(|output| output.amount).sum();

    if mint_quote.amount != outputs_amount {
      return Err(MintError::AmountsDoNotMatch);
    }

    let mut signatures: BlindSignatures = vec![];
    for output in outputs {
      let signature = self.mint_token(output)?;
      signatures.push(signature);
    }

    Ok(PostMintBolt11Response { signatures })
  }

  // Signs blinded message (an output)
  fn mint_token(&self, message: BlindedMessage) -> Result<BlindSignature> {
    let BlindedMessage { b, id, amount } = message;

    let secretkey = match self.get_secret_key_from_keyset_id_and_amount(id.clone(), amount) {
      Ok(s) => s,
      Err(e) => return Err(e),
    };

    let secp = Secp256k1::new();
    let scalar = Scalar::from(secretkey);
    // calculate C_ = kB_
    let c_ = match b.mul_tweak(&secp, &scalar) {
      Ok(c) => c,
      Err(e) => return Err(MintError::InvalidECMath(format!("[mul_tweak|mint] {}", e))),
    };

    // Bob sends back to Alice blinded key (promise): C_ = kB_ (these two steps are the DH -blind- key exchange) (signing)
    Ok(BlindSignature { amount, id, c: c_ })
  }

  // checks that k*hash_to_curve(x) == C
  fn verify_input(&self, input: Proof) -> Result<bool> {
    let Proof {
      secret,
      c,
      id,
      amount,
    } = input;

    let secretkey = match self.get_secret_key_from_keyset_id_and_amount(id, amount) {
      Ok(s) => s,
      Err(e) => return Err(e),
    };

    let x = hex::decode(secret).unwrap();

    let y = hash_to_curve(x);
    let secp = Secp256k1::new();
    let scalar = Scalar::from(secretkey);
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

  fn get_secret_key_from_keyset_id_and_amount(
    &self,
    keyset_id: String,
    amount: Amount,
  ) -> Result<SecretKey> {
    // Get secretkey used to create the blind signature
    let secretkey = match self.keysets.iter().find(|keyset| keyset.id == keyset_id) {
      Some(keyset) => {
        let publickey = keyset.keys.get(&amount);
        if publickey.is_none() {
          return Err(MintError::InvalidProof);
        }

        let secretkey = self
          .keypairs
          .iter()
          .find(|keypair| keypair.pubkey == *publickey.unwrap());
        if secretkey.is_none() {
          return Err(MintError::InvalidProof);
        }

        secretkey.unwrap().secretkey
      }
      None => return Err(MintError::InvalidProof),
    };

    Ok(secretkey)
  }
}

#[cfg(test)]
mod tests {
  use bitcoin::secp256k1::{PublicKey, SecretKey};
  use serde_json::json;
  use std::{fs, str::FromStr};

  use crate::types::Keypair;

  use super::*;

  struct Sut {
    mint: Mint,
    db_name: String,
  }

  impl Drop for Sut {
    fn drop(&mut self) {
      self.remove_temp_db();
    }
  }

  impl Sut {
    fn new(db_name: &str) -> Self {
      let keypairs = Self::gen_keypairs();
      let keyset = Self::gen_keyset();
      let mint = Mint::new_testing_mint(db_name, keyset, keypairs);

      Self {
        mint,
        db_name: db_name.to_string(),
      }
    }

    fn gen_keypairs() -> Keypairs {
      let pubkey =
        PublicKey::from_str("02ec4a46e8d58aa75f03dc40a6ba58330fcb7d2c15ef99f901eca18d9d3bc6ec4e")
          .unwrap();
      let secretkey =
        SecretKey::from_str("407218161f9f183768fcd1904b3180a89f9680ea5fd72f69a6ac7ef334aea2b3")
          .unwrap();
      let keypair0 = Keypair { pubkey, secretkey };

      let pubkey =
        PublicKey::from_str("0205ff05dd6445526443edf55e7d48527fc33c877fe12a7bdd78a2346cf8f3c25c")
          .unwrap();
      let secretkey =
        SecretKey::from_str("cf98e066d0995199aa87d50057c76f39bc27597d3ebede0724b00b0170e2fea3")
          .unwrap();
      let keypair1 = Keypair { pubkey, secretkey };

      let pubkey =
        PublicKey::from_str("03e6d8b7552150691f196672b4f727317d7318f5a05528019bacc12d559f106706")
          .unwrap();
      let secretkey =
        SecretKey::from_str("b8124a9f1b89b80f59c5663565926b3dbb219718cab2755a1c1d88b958eb760b")
          .unwrap();
      let keypair2 = Keypair { pubkey, secretkey };

      let keypairs: Keypairs = vec![keypair0, keypair1, keypair2];

      keypairs
    }

    fn gen_keyset() -> KeysetWithKeys {
      let keyset = json!(
        {
          "id": "009a1f293253e41e",
          "unit": "sat",
          "active": true,
          "keys": {
              "1": "02ec4a46e8d58aa75f03dc40a6ba58330fcb7d2c15ef99f901eca18d9d3bc6ec4e", // keypair0.pubkey
              "2": "0205ff05dd6445526443edf55e7d48527fc33c877fe12a7bdd78a2346cf8f3c25c", // keypair1.pubkey
              "4": "03e6d8b7552150691f196672b4f727317d7318f5a05528019bacc12d559f106706", // keypair2.pubkey
          }
        }
      );
      let keyset: KeysetWithKeys = serde_json::from_value(keyset).unwrap();
      keyset
    }

    fn gen_proofs_created_from_this_mint() -> Proofs {
      let proof_1 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "secret": "12aba1f293ae53e41e",
          "amount": 1,
          "C": PublicKey::from_str("03d4150de41eb44fcad2d4e57abbb21e0674d7277a5cfe86e782a74afe299dd8f4").unwrap(),
        }
      );
      let proof_2 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "secret": "31baaba1f293ae53e41e",
          "amount": 2,
          "C": PublicKey::from_str("02393a930aff0ed1acba8292dc13d666c22210c81183a355f060d3e73d5176ed19").unwrap(),
        }
      );
      let proof_3 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "secret": "44baaba1f293ae53e41e",
          "amount": 4,
          "C": PublicKey::from_str("0205fc448d731e91488e3ec5c15c59dcf671edad677955cd978153302c1a5af4ea").unwrap(),
        }
      );
      let proof1: Proof = serde_json::from_value(proof_1).unwrap();
      let proof2: Proof = serde_json::from_value(proof_2).unwrap();
      let proof3: Proof = serde_json::from_value(proof_3).unwrap();

      let proofs = vec![proof1, proof2, proof3];
      proofs
    }

    fn gen_proofs_created_from_this_mint_millisats() -> Proofs {
      let proof_1 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "secret": "12aba1f293ae53e41e",
          "amount": 1000,
          "C": PublicKey::from_str("03d4150de41eb44fcad2d4e57abbb21e0674d7277a5cfe86e782a74afe299dd8f4").unwrap(),
        }
      );
      let proof_2 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "secret": "31baaba1f293ae53e41e",
          "amount": 2000,
          "C": PublicKey::from_str("02393a930aff0ed1acba8292dc13d666c22210c81183a355f060d3e73d5176ed19").unwrap(),
        }
      );
      let proof_3 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "secret": "44baaba1f293ae53e41e",
          "amount": 4000,
          "C": PublicKey::from_str("0205fc448d731e91488e3ec5c15c59dcf671edad677955cd978153302c1a5af4ea").unwrap(),
        }
      );
      let proof1: Proof = serde_json::from_value(proof_1).unwrap();
      let proof2: Proof = serde_json::from_value(proof_2).unwrap();
      let proof3: Proof = serde_json::from_value(proof_3).unwrap();

      let proofs = vec![proof1, proof2, proof3];
      proofs
    }

    fn gen_proofs_not_created_from_this_mint() -> Proofs {
      let proof_1 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "secret": "12aba1f293ae53e41e", // c != ky
          "amount": 1,
          "C": PublicKey::from_str("02ec4a46e8d58aa75f03dc40a6ba58330fcb7d2c15ef99f901eca18d9d3bc6ec4e").unwrap(),
        }
      );
      let proof_2 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "secret": "31baaba1f293ae53e41e", // c == ky (if the amount is 2)
          "amount": 64, // amount not supported by mint
          "C": PublicKey::from_str("02393a930aff0ed1acba8292dc13d666c22210c81183a355f060d3e73d5176ed19").unwrap(),
        }
      );
      let proof_3 = json!(
        {
          "id": "deadbeef", // wrong keysetid
          "secret": "44baaba1f293ae53e41e", // c == ky (if the amount is 4)
          "amount": 4,
          "C": PublicKey::from_str("0205fc448d731e91488e3ec5c15c59dcf671edad677955cd978153302c1a5af4ea").unwrap(),
        }
      );
      let proof1: Proof = serde_json::from_value(proof_1).unwrap();
      let proof2: Proof = serde_json::from_value(proof_2).unwrap();
      let proof3: Proof = serde_json::from_value(proof_3).unwrap();

      let proofs = vec![proof1, proof2, proof3];
      proofs
    }

    fn gen_blinded_messages() -> BlindedMessages {
      let blinded_message_1 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "amount": 1,
          "B_": PublicKey::from_str("02d4ecdbc6daf91de5165562108ee7313d4e6a0d92dee9c9c52eec905b2ae283b5").unwrap(),
        }
      );
      let blinded_message_2 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "amount": 2,
          "B_": PublicKey::from_str("03f09469008c9bd9eeb0e1452e7bdd4ee4dc5f2dabdb997024997b156c5cbc3058").unwrap(),
        }
      );
      let blinded_message_3 = json!(
        {
          "id": "009a1f293253e41e", // same id as the keyset
          "amount": 4,
          "B_": PublicKey::from_str("035b2531e2ba24d3720413fb691dba27a67a6d165df553d1d5bc428973c547623c").unwrap(),
        }
      );
      let blinded_message1: BlindedMessage = serde_json::from_value(blinded_message_1).unwrap();
      let blinded_message2: BlindedMessage = serde_json::from_value(blinded_message_2).unwrap();
      let blinded_message3: BlindedMessage = serde_json::from_value(blinded_message_3).unwrap();

      let blinded_messages = vec![blinded_message1, blinded_message2, blinded_message3];
      blinded_messages
    }

    fn gen_invalid_blinded_messages() -> BlindedMessages {
      let blinded_message_1 = json!(
        {
          "id": "109a1f293253e41e", // different id from the keyset
          "amount": 1,
          "B_": PublicKey::from_str("02d4ecdbc6daf91de5165562108ee7313d4e6a0d92dee9c9c52eec905b2ae283b5").unwrap(),
        }
      );
      let blinded_message_2 = json!(
        {
          "id": "209a1f293253e41e", // different id from the keyset
          "amount": 2,
          "B_": PublicKey::from_str("03f09469008c9bd9eeb0e1452e7bdd4ee4dc5f2dabdb997024997b156c5cbc3058").unwrap(),
        }
      );
      let blinded_message_3 = json!(
        {
          "id": "309a1f293253e41e", // different id from the keyset
          "amount": 4,
          "B_": PublicKey::from_str("035b2531e2ba24d3720413fb691dba27a67a6d165df553d1d5bc428973c547623c").unwrap(),
        }
      );
      let blinded_message1: BlindedMessage = serde_json::from_value(blinded_message_1).unwrap();
      let blinded_message2: BlindedMessage = serde_json::from_value(blinded_message_2).unwrap();
      let blinded_message3: BlindedMessage = serde_json::from_value(blinded_message_3).unwrap();

      let blinded_messages = vec![blinded_message1, blinded_message2, blinded_message3];
      blinded_messages
    }

    fn gen_blind_signatures() -> BlindSignatures {
      let keypairs = Sut::gen_keypairs();
      let blinded_messages = Sut::gen_blinded_messages();
      let secp = Secp256k1::new();

      let mut blinded_signatures: BlindSignatures = vec![];

      for (i, keypair) in keypairs.iter().enumerate() {
        let secretkey = keypair.secretkey;
        let b_ = blinded_messages[i].b;

        let scalar = Scalar::from(secretkey);
        // calculate C_ = kB_
        let c_ = match b_.mul_tweak(&secp, &scalar) {
          Ok(c) => c,
          Err(_e) => panic!(),
        };

        let blind_signature = BlindSignature {
          c: c_,
          amount: blinded_messages[i].amount,
          id: blinded_messages[i].clone().id,
        };

        blinded_signatures.push(blind_signature);
      }

      blinded_signatures
    }

    fn gen_mint_quotes() -> Vec<PostMintQuoteBolt11Response> {
      // Generate a valid paid quote
      let quote1 = PostMintQuoteBolt11Response {
        expiry: 1714038710,
        quote: "f3091ac2-3ba7-442e-a330-2d12bf5d3a95".to_string(),
        paid: true,
        request: "ln1230940something".to_string(),
        amount: 7,
      };

      // Generate a valid unpaid quote
      let quote2 = PostMintQuoteBolt11Response {
        expiry: 1814038710,
        quote: "e3091ac2-3ba7-442e-a330-2d12bf5d3a95".to_string(),
        paid: false,
        request: "ln2230940something".to_string(),
        amount: 7,
      };

      // Generate an unvalid quote (amounts don't match)
      let quote3 = PostMintQuoteBolt11Response {
        expiry: 1914038710,
        quote: "d3091ac2-3ba7-442e-a330-2d12bf5d3a95".to_string(),
        paid: true,
        request: "ln3230940something".to_string(),
        amount: 4,
      };

      [quote1, quote2, quote3].to_vec()
    }

    fn remove_temp_db(&self) {
      fs::remove_file(format!("db/test/{}.redb", self.db_name)).unwrap();
    }
  }

  #[test]
  fn mint_info() {
    let sut = Sut::new("mint_info");

    // test (de)serialization
    let json_str = r#"
    {
      "name": "Bob's Cashu mint",
      "pubkey": "0283bf290884eed3a7ca2663fc0260de2e2064d6b355ea13f98dec004b7a7ead99",
      "version": "Nutshell/0.15.0",
      "description": "The short mint description",
      "description_long": "A description that can be a long piece of text.",
      "contact": [
        ["email", "contact@me.com"],
        ["twitter", "@me"],
        ["nostr" ,"npub..."]
      ],  
      "motd": "Message to display to users.",  
      "nuts": {
        "4": {
          "methods": [
            {
              "method": "bolt11",
              "unit": "sat",
              "min_amount": 0,
              "max_amount": 10000        
            }
          ],
          "disabled": false
        },
        "5": {
          "methods": [
            {
              "method": "bolt11",
              "unit": "sat",
              "min_amount": 100,
              "max_amount": 10000        
            }
          ],
          "disabled": false
        },
        "7": {"supported": true},
        "8": {"supported": true},
        "9": {"supported": true},
        "10": {"supported": true},
        "12": {"supported": true}
      }
    }
    "#;

    let nut04 = r#"
      {
        "methods": [
          {
            "method": "bolt11",
            "unit": "sat",
            "min_amount": 0,
            "max_amount": 10000        
          }
        ],
        "disabled": false
      }
    "#;
    let nut04_deserialized: Nut = serde_json::from_str(nut04).unwrap();

    let deserialized: GetInfoResponse = serde_json::from_str(json_str).unwrap();

    assert_eq!(deserialized.name, "Bob's Cashu mint");
    assert_eq!(deserialized.contact[0][0], "email");
    assert_eq!(deserialized.contact[0][1], "contact@me.com");
    assert_eq!(deserialized.nuts.get("11"), None);
    assert_eq!(
      deserialized.nuts.get("4"),
      Some(NutValue::Nut(nut04_deserialized.clone())).as_ref()
    );

    let mint_info = sut.mint.info();

    assert_eq!(mint_info.name, "Guilospanck's mint");
    assert_eq!(mint_info.contact[0][0], "email");
    assert_eq!(mint_info.contact[0][1], "guilospanck@protonmail.com");
    assert_eq!(mint_info.nuts.get("11"), None);
    assert_eq!(
      mint_info.nuts.get("4"),
      Some(NutValue::Nut(nut04_deserialized)).as_ref()
    );
  }

  #[test]
  fn verify_input() {
    let sut = Sut::new("verify_input");
    let valid_proofs = Sut::gen_proofs_created_from_this_mint();
    let not_valid_proofs = Sut::gen_proofs_not_created_from_this_mint();

    // valid proofs for this mint
    let result0 = sut.mint.verify_input(valid_proofs[0].clone()).unwrap();
    assert!(result0);
    let result1 = sut.mint.verify_input(valid_proofs[1].clone()).unwrap();
    assert!(result1);
    let result2 = sut.mint.verify_input(valid_proofs[2].clone()).unwrap();
    assert!(result2);

    // c != ky
    let result0 = sut.mint.verify_input(not_valid_proofs[0].clone()).unwrap();
    assert!(!result0);

    // amount not supported by mint
    let result1 = sut.mint.verify_input(not_valid_proofs[1].clone());
    assert!(result1.is_err_and(|x| x == MintError::InvalidProof));

    // keyset id not found
    let result2 = sut.mint.verify_input(not_valid_proofs[2].clone());
    assert!(result2.is_err_and(|x| x == MintError::InvalidProof));
  }

  #[test]
  fn swap_tokens() {
    let mut sut = Sut::new("swap_tokens");
    let outputs = Sut::gen_blinded_messages();
    let mut outputs_with_wrong_amount = outputs.clone();
    outputs_with_wrong_amount[0].amount = 64;
    let valid_inputs = Sut::gen_proofs_created_from_this_mint();
    let mut not_valid_proofs = Sut::gen_proofs_not_created_from_this_mint();
    not_valid_proofs[1].amount = 2; // So we match the amounts

    // InsufficientFunds
    let input_with_less_than_output = sut
      .mint
      .swap_tokens(valid_inputs.clone(), outputs_with_wrong_amount);
    assert!(input_with_less_than_output.is_err_and(|x| x == MintError::InsufficientFunds));

    // first time swapping tokens should work
    let res_ok = sut.mint.swap_tokens(valid_inputs.clone(), outputs.clone());
    assert!(res_ok.is_ok_and(|x| x.len() == outputs.len()));

    // second time swapping tokens should not work (tokens should be invalidated)
    let res_ok = sut.mint.swap_tokens(valid_inputs, outputs.clone());
    assert!(res_ok.is_err_and(|x| x == MintError::InvalidProof));

    // using not valid proofs should not work
    let res_ok = sut.mint.swap_tokens(not_valid_proofs, outputs);
    assert!(res_ok.is_err_and(|x| x == MintError::InvalidProof));
  }

  #[test]
  fn mint_quote() {
    let mut sut = Sut::new("mint_quote");
    let amount = 7;
    let unit = Unit::SAT;
    let expected_expiry = Utc::now().timestamp() + 3600;
    let expected_response = PostMintQuoteBolt11Response {
      expiry: expected_expiry,
      paid: false,
      quote: "some-random-string".to_string(),
      request: "bolt11invoicerequest".to_string(),
      amount,
    };

    // valid payment method
    let payment_method = PaymentMethod::BOLT11;
    let res_ok = sut
      .mint
      .mint_quote(payment_method, amount, unit.clone())
      .unwrap();
    assert_eq!(res_ok.paid, expected_response.paid);
    assert_eq!(res_ok.expiry, expected_response.expiry);
    assert!(res_ok.request.starts_with("ln"));
    println!("{}", res_ok.request);

    // invalid payment method
    let payment_method = PaymentMethod::OTHER;
    let res_ok = sut.mint.mint_quote(payment_method, amount, unit);
    assert!(res_ok.is_err_and(|x| x == MintError::PaymentMethodNotSupported));
  }

  #[test]
  fn melt_quote() {
    let mut sut = Sut::new("melt_quote");
    let request = "lnbc690p1pnfqvjkdqcf9h8vmmfvdjjqcmjv4shgetypp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp59g4z52329g4z52329g4z52329g4z52329g4z52329g4z52329g4q9qrsgqcqzysxqrrss2sf0ed8mg23arqg5gwa38z3937lxpkaxxxccs89ttw7kh6dl63krwxsjrd6paxcahktsrhqq8m9zp5tyekvdq4ckx580qnwwhpg40kgqela3pz".to_string();

    let melt_request = PostMeltQuoteBolt11Request {
      unit: Unit::SAT,
      request,
    };

    let amount = 69;
    let expected_expiry = 3600;
    let expected_response = PostMeltQuoteBolt11Response {
      expiry: expected_expiry,
      paid: false,
      quote: "some-random-string".to_string(),
      amount: amount * 1000,
      fee_reserve: 0,
    };

    let res_ok = sut.mint.melt_quote(melt_request).unwrap();
    assert_eq!(res_ok.paid, expected_response.paid);
    assert_eq!(res_ok.expiry, expected_response.expiry);
    assert_eq!(res_ok.amount, expected_response.amount);
  }

  #[test]
  fn melt() {
    let mut sut = Sut::new("melt");

    let request = "lnbc690p1pnfqvjkdqcf9h8vmmfvdjjqcmjv4shgetypp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp59g4z52329g4z52329g4z52329g4z52329g4z52329g4z52329g4q9qrsgqcqzysxqrrss2sf0ed8mg23arqg5gwa38z3937lxpkaxxxccs89ttw7kh6dl63krwxsjrd6paxcahktsrhqq8m9zp5tyekvdq4ckx580qnwwhpg40kgqela3pz".to_string();
    let melt_request = PostMeltQuoteBolt11Request {
      unit: Unit::SAT,
      request,
    };
    let melt_quote = sut.mint.melt_quote(melt_request).unwrap();
    let quote = melt_quote.quote;
    let inputs = Sut::gen_proofs_created_from_this_mint_millisats();

    // Check err when quote does not exist
    let with_inexistant_quote = PostMeltBolt11Request {
      quote: String::from("potato"),
      inputs: vec![],
    };
    let res_ok = sut.mint.melt(with_inexistant_quote);
    assert_eq!(res_ok, Err(MintError::MeltQuoteNotFound("".to_string())));

    // Check when not enough funds
    let with_insufficient_funds = PostMeltBolt11Request {
      quote,
      inputs: inputs.clone(),
    };
    let res_ok = sut.mint.melt(with_insufficient_funds);
    assert_eq!(res_ok, Err(MintError::InsufficientFunds));

    // Check ok
    sut.mint.payment_preimage = Some([0; 32].to_vec());
    let request = "lnbc70p1pnfq04xdqcf9h8vmmfvdjjqcmjv4shgetypp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp59g4z52329g4z52329g4z52329g4z52329g4z52329g4z52329g4q9qrsgqcqzysxqrrssxwyd49mwq9rf788v07xmgq6hhca45gtk0h3qty4m4f7cja8al79p0gpsz2rnvupujjttlxrud2ylm7ffyzakn2yl72e5wlv0wnju0tspvc99ng".to_string();
    let melt_request = PostMeltQuoteBolt11Request {
      unit: Unit::SAT,
      request,
    };
    let melt_quote = sut.mint.melt_quote(melt_request).unwrap();
    let quote = melt_quote.quote;

    let with_sufficient_funds = PostMeltBolt11Request { quote, inputs };
    let _ = sut.mint.melt(with_sufficient_funds).unwrap();
  }

  #[test]
  fn check_mint_quote_state() {
    let mut sut = Sut::new("check_mint_quote_state");
    let invalid_quote_id = "invalidquoteid".to_string();

    // check invalid quote
    let res_ok = sut.mint.check_mint_quote_state(invalid_quote_id);
    assert!(res_ok.is_err_and(|x| matches!(x, MintError::MintQuoteNotFound(_))));

    // mint quote
    let method = PaymentMethod::BOLT11;
    let amount: Amount = 1;
    let unit = Unit::SAT;
    let mint_quote = sut.mint.mint_quote(method, amount, unit).unwrap();

    // check valid quote_id
    let res_ok = sut
      .mint
      .check_mint_quote_state(mint_quote.clone().quote)
      .unwrap();
    assert_eq!(res_ok.quote, mint_quote.quote);
    assert!(!res_ok.paid);
    assert_eq!(res_ok.expiry, mint_quote.expiry);
  }

  #[test]
  fn mint() {
    let mut sut = Sut::new("mint");
    let valid_outputs = Sut::gen_blinded_messages();
    let expected_signatures = Sut::gen_blind_signatures();
    let method = PaymentMethod::BOLT11;
    let invalid_method = PaymentMethod::OTHER;
    let mint_quotes = Sut::gen_mint_quotes();

    for mint_quote in mint_quotes.clone() {
      sut.mint.db.write_to_mint_quotes_table(mint_quote).unwrap();
    }

    let res_ok = sut
      .mint
      .mint(
        method.clone(),
        PostMintBolt11Request {
          quote_id: mint_quotes[0].quote.clone(),
          outputs: valid_outputs.clone(),
        },
      )
      .unwrap();
    assert_eq!(res_ok.signatures, expected_signatures);

    let res_ok = sut.mint.mint(
      method.clone(),
      PostMintBolt11Request {
        quote_id: mint_quotes[1].quote.clone(),
        outputs: valid_outputs.clone(),
      },
    );
    assert!(res_ok.is_err_and(|x| x == MintError::MintQuoteNotPaid));

    let res_ok = sut.mint.mint(
      method,
      PostMintBolt11Request {
        quote_id: mint_quotes[2].quote.clone(),
        outputs: valid_outputs.clone(),
      },
    );
    assert!(res_ok.is_err_and(|x| x == MintError::AmountsDoNotMatch));

    let res_ok = sut.mint.mint(
      invalid_method,
      PostMintBolt11Request {
        quote_id: mint_quotes[0].quote.clone(),
        outputs: valid_outputs,
      },
    );
    assert!(res_ok.is_err_and(|x| x == MintError::PaymentMethodNotSupported));
  }

  #[test]
  fn mint_tokens() {
    let sut = Sut::new("mint_token");
    let valid_outputs = Sut::gen_blinded_messages();
    let invalid_outputs = Sut::gen_invalid_blinded_messages();
    let expected_signatures = Sut::gen_blind_signatures();

    // valid outputs
    for i in 0..valid_outputs.len() {
      let res_ok = sut.mint.mint_token(valid_outputs[i].clone()).unwrap();
      assert_eq!(res_ok, expected_signatures[i]);
    }

    // invalid outputs
    for invalid_output in invalid_outputs {
      let res_ok = sut.mint.mint_token(invalid_output);
      assert!(res_ok.is_err_and(|x| x == MintError::InvalidProof));
    }
  }

  #[test]
  fn get_secret_key_from_keyset_id_and_amount() {
    let sut = Sut::new("get_secret_key_from_keyset_id_and_amount");
    let keyset = Sut::gen_keyset();
    let keypairs = Sut::gen_keypairs();
    let keyset_id = keyset.id;
    let keys = keyset.keys;

    // valid amounts and keyset_id
    for (idx, (amount, _)) in keys.iter().enumerate() {
      let res_ok = sut
        .mint
        .get_secret_key_from_keyset_id_and_amount(keyset_id.clone(), *amount)
        .unwrap();
      assert_eq!(res_ok, keypairs[idx].secretkey);
    }

    // valid keyset_id, invalid amount
    let res_ok = sut
      .mint
      .get_secret_key_from_keyset_id_and_amount(keyset_id, 256);
    assert!(res_ok.is_err_and(|x| x == MintError::InvalidProof));

    // invalid keyset_id, valid amount
    let res_ok = sut
      .mint
      .get_secret_key_from_keyset_id_and_amount("deadbeef".to_string(), 1);
    assert!(res_ok.is_err_and(|x| x == MintError::InvalidProof));
  }
}
