use std::result;

use bitcoin::{key::Secp256k1, secp256k1::Scalar};

use crate::{
  database::{CashuDatabase, DBType},
  helpers::hash_to_curve,
  keyset::{generate_keyset_and_keypairs, Keyset, KeysetWithKeys, Keysets},
  rest::{GetKeysResponse, GetKeysetsResponse},
  types::{
    BlindSignature, BlindSignatures, BlindedMessage, BlindedMessages, Keypairs, Proof, Proofs,
  },
};

/// [`Mint`] error
#[derive(thiserror::Error, Debug)]
pub enum MintError {
  #[error("Invalid EC math: `{0}`")]
  InvalidECMath(String),
  #[error("Error verifying proof: `{0}`")]
  ErrorVerifyingProof(String),
  #[error("Invalid proof")]
  InvalidProof,
  #[error("Amounts don't match")]
  AmountsDoNotMatch,
}

type Result<T> = result::Result<T, MintError>;

pub struct Mint {
  keysets: Vec<KeysetWithKeys>,
  keypairs: Keypairs,
  db: CashuDatabase,
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

    Self {
      keysets,
      keypairs,
      db,
    }
  }

  fn new_testing_mint(db_name: &str, keyset: KeysetWithKeys, keypairs: Keypairs) -> Self {
    let db = CashuDatabase::new_testing_db(db_name).unwrap();
    let keysets = vec![keyset];

    Self {
      keysets,
      keypairs,
      db,
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
    if total_amount_inputs != total_amount_outputs {
      return Err(MintError::AmountsDoNotMatch);
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

  // Signs blinded message (an output)
  pub fn mint_token(&self, message: BlindedMessage) -> Result<BlindSignature> {
    let BlindedMessage { b, id, amount } = message;

    // TODO: not sure about this
    let secretkey = self
      .keypairs
      .iter()
      .find(|keypair| keypair.pubkey == b)
      .unwrap()
      .secretkey;

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

    // Get secretkey used to create the blind signature
    let secretkey = match self.keysets.iter().find(|keyset| keyset.id == id) {
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
}

#[cfg(test)]
mod tests {
  use bitcoin::secp256k1::{PublicKey, SecretKey};
  use serde_json::json;
  use std::str::FromStr;

  use crate::types::Keypair;

  use super::*;

  struct Sut {
    mint: Mint,
  }
  impl Sut {
    fn new(db_name: &str) -> Self {
      let keypairs = Self::gen_keypairs();
      let keyset = Self::gen_keyset();
      let mint = Mint::new_testing_mint(db_name, keyset, keypairs);

      Self { mint }
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

    fn gen_proofs_not_created_from_this_mint() -> Proofs {
      let proof_1 = json!(
        {
          "id": "009a1f293253e41e",
          "secret": "12aba1f293ae53e41e",
          "amount": 64,
          "C": PublicKey::from_str("02ec4a46e8d58aa75f03dc40a6ba58330fcb7d2c15ef99f901eca18d9d3bc6ec4e").unwrap(),
        }
      );
      let proof_2 = json!(
        {
          "id": "129a1f293253e41e",
          "secret": "31baaba1f293ae53e41e",
          "amount": 8,
          "C": PublicKey::from_str("0205ff05dd6445526443edf55e7d48527fc33c877fe12a7bdd78a2346cf8f3c25c").unwrap(),
        }
      );
      let proof_3 = json!(
        {
          "id": "1abcde1f293253e41e",
          "secret": "44baaba1f293ae53e41e",
          "amount": 16,
          "C": PublicKey::from_str("03e6d8b7552150691f196672b4f727317d7318f5a05528019bacc12d559f106706").unwrap(),
        }
      );
      let proof1: Proof = serde_json::from_value(proof_1).unwrap();
      let proof2: Proof = serde_json::from_value(proof_2).unwrap();
      let proof3: Proof = serde_json::from_value(proof_3).unwrap();

      let proofs = vec![proof1, proof2, proof3];
      proofs
    }
  }

  #[test]
  fn verify_input() {
    let sut = Sut::new("verify_input");
    let valid_proofs = Sut::gen_proofs_created_from_this_mint();
    let _not_valid_proofs = Sut::gen_proofs_not_created_from_this_mint();

    let result0 = sut.mint.verify_input(valid_proofs[0].clone()).unwrap();
    assert!(result0);
    let result1 = sut.mint.verify_input(valid_proofs[1].clone()).unwrap();
    assert!(result1);
    let result2 = sut.mint.verify_input(valid_proofs[2].clone()).unwrap();
    assert!(result2);
  }
}
