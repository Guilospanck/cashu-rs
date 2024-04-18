use std::result;

use serde::{Deserialize, Serialize};

use bitcoin::{
  key::Secp256k1,
  secp256k1::{PublicKey, Scalar},
};

use crate::{
  database::{CashuDatabase, DBType},
  helpers::hash_to_curve,
  keyset::{generate_keyset_and_keypairs, Keyset, KeysetWithKeys, Keysets},
  rest::{GetKeysResponse, GetKeysetsResponse},
  types::{BlindSignature, BlindSignatures, BlindedMessage, BlindedMessages, Keypairs, Proofs},
};

/// [`Mint`] error
#[derive(thiserror::Error, Debug)]
pub enum MintError {
  #[error("Invalid EC math: `{0}`")]
  InvalidECMath(String),
}

type Result<T> = result::Result<T, MintError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Mint {
  keysets: Vec<KeysetWithKeys>,
  keypairs: Keypairs,
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

    Self { keysets, keypairs }
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

  pub fn swap_tokens(&self, _inputs: Proofs, _outputs: BlindedMessages) -> Result<BlindSignatures> {
    unimplemented!()
  }

  // Signs blinded message (an output)
  pub fn mint_or_swap_tokens(&self, message: BlindedMessage) -> Result<BlindSignature> {
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
  pub fn verification(&self, x: Vec<u8>, c: PublicKey) -> Result<bool> {
    // TODO: not sure about this
    let secretkey = self
      .keypairs
      .iter()
      .find(|keypair| keypair.pubkey == c)
      .unwrap()
      .secretkey;

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
