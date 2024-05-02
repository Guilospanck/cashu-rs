use bitcoin::secp256k1::{Error as Secp256k1Error, PublicKey, SecretKey};
use redb::{Database, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Deserializer, Serialize};
use std::{fs, result, str::FromStr};
use strum::{EnumString, IntoStaticStr};

use crate::{
  helpers::sha256_hasher,
  keyset::KeysetWithKeys,
  rest::PostMintQuoteBolt11Response,
  types::{Amount, Keypair, Keypairs, Proof, Proofs, Token, Tokens},
};

/// [`Database`] error
#[derive(thiserror::Error, Debug)]
pub enum CashuDatabaseError {
  /// General errors related to redb::Error
  #[error(transparent)]
  RedbGeneral(#[from] redb::Error),

  /// Transaction errors related to redb::TransactionError
  #[error(transparent)]
  RedbTransaction(#[from] redb::TransactionError),

  /// Database errors related to redb::DatabaseError
  #[error(transparent)]
  RedbDatabase(#[from] redb::DatabaseError),

  /// Table errors related to redb::TableError
  #[error(transparent)]
  RedbTable(#[from] redb::TableError),

  /// Commit errors related to redb::CommitError
  #[error(transparent)]
  RedbCommit(#[from] redb::CommitError),

  /// Storage errors related to redb::StorageError
  #[error(transparent)]
  RedbStorage(#[from] redb::StorageError),

  /// Error related to serde_json::Error
  #[error(transparent)]
  Serde(#[from] serde_json::Error),

  /// Error related to std::io::Error
  #[error(transparent)]
  IO(#[from] std::io::Error),

  /// Error related to Secp256k1Error
  #[error(transparent)]
  SECP256K1(#[from] Secp256k1Error),
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Serialize, Clone, EnumString, IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
pub enum DBType {
  MINT,
  WALLET,
}

impl<'de> Deserialize<'de> for DBType {
  fn deserialize<D>(deserializer: D) -> result::Result<DBType, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s: String = Deserialize::deserialize(deserializer)?;
    DBType::from_str(&s.to_lowercase()).map_err(serde::de::Error::custom)
  }
}

type Result<T> = result::Result<T, CashuDatabaseError>;

pub struct CashuDatabase {
  db: Database,
}

impl CashuDatabase {
  /// MINT
  // keyset_id, KeysetWithKeys
  const MINT_KEYSETS_TABLE: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("keysets");
  // pubkey, seckey
  const MINT_KEYPAIRS_TABLE: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("keypairs");
  // date, proof
  const MINT_INVALID_INPUTS_TABLE: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("invalid_proofs");
  // quote_id, PostMintQuoteBolt11Response
  const MINT_QUOTES_TABLE: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("mint_quotes");

  /// WALLET
  // mint_url, proofs
  const WALLET_PROOFS_TABLE: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("proofs");
  // quote_id, amount
  const WALLET_QUOTES_TABLE: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("wallet_quotes");

  pub fn new(db_type: DBType) -> Result<Self> {
    CashuDatabase::initialise_db(db_type)
  }

  pub fn new_testing_db(db_name: &str) -> Result<Self> {
    CashuDatabase::initialise_test_db(db_name)
  }

  pub fn write_to_keypairs_table(&mut self, k: PublicKey, v: SecretKey) -> Result<()> {
    let pubkey_serialized = hex::encode(k.serialize());
    let seckey_serialized = v.display_secret().to_string();
    let write_txn = self.begin_write()?;
    {
      let mut table = write_txn.open_table(Self::MINT_KEYPAIRS_TABLE)?;
      table.insert(pubkey_serialized.as_str(), seckey_serialized.as_str())?;
    }
    self.commit_txn(write_txn)?;
    Ok(())
  }

  pub fn get_all_keypairs(&self) -> Result<Keypairs> {
    let mut keypairs: Keypairs = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::MINT_KEYPAIRS_TABLE)?;

    table.iter().unwrap().for_each(|keypair| {
      let evt = keypair.unwrap();
      let pubkey_value = evt.0.value();
      let seckey_value = evt.1.value();

      let pubkey = PublicKey::from_str(pubkey_value).unwrap();
      let secretkey = SecretKey::from_str(seckey_value).unwrap();

      let keypair = Keypair { pubkey, secretkey };

      keypairs.push(keypair);
    });

    Ok(keypairs)
  }

  pub fn write_to_keysets_table(&mut self, k: &str, v: KeysetWithKeys) -> Result<()> {
    let value_serialized = serde_json::to_string(&v)?;
    let write_txn = self.begin_write()?;
    {
      let mut table = write_txn.open_table(Self::MINT_KEYSETS_TABLE)?;
      table.insert(k, value_serialized.as_str())?;
    }
    self.commit_txn(write_txn)?;
    Ok(())
  }

  pub fn get_all_keysets(&self) -> Result<Vec<KeysetWithKeys>> {
    let mut keysets: Vec<KeysetWithKeys> = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::MINT_KEYSETS_TABLE)?;

    table.iter().unwrap().for_each(|keyset| {
      let evt = keyset.unwrap();
      let keyset_value = evt.1.value();
      let keyset_deserialized: KeysetWithKeys = serde_json::from_str(keyset_value).unwrap();
      keysets.push(keyset_deserialized);
    });

    Ok(keysets)
  }

  pub fn write_to_wallet_proofs_table(&mut self, mint_url: &str, proofs: Proofs) -> Result<()> {
    let proofs_serialized = serde_json::to_string(&proofs)?;
    let write_txn = self.begin_write()?;
    {
      let mut table = write_txn.open_table(Self::WALLET_PROOFS_TABLE)?;
      table.insert(mint_url, proofs_serialized.as_str())?;
    }
    self.commit_txn(write_txn)?;
    Ok(())
  }

  pub fn get_all_tokens(&self) -> Result<Tokens> {
    let mut tokens: Tokens = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::WALLET_PROOFS_TABLE)?;

    table.iter().unwrap().for_each(|keyset| {
      let evt = keyset.unwrap();
      let mint_url = evt.0.value();
      let mint_proofs = evt.1.value();
      let mint_proofs_deserialized: Proofs = serde_json::from_str(mint_proofs).unwrap();
      tokens.push(Token {
        mint: mint_url.to_string(),
        proofs: mint_proofs_deserialized,
      });
    });

    Ok(tokens)
  }

  pub fn get_all_proofs_from_mint(&self, mint_url: String) -> Result<Proofs> {
    let mut proofs: Proofs = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::WALLET_PROOFS_TABLE)?;

    if let Ok(Some(mint_proofs)) = table.get(mint_url.as_str()) {
      let mint_proofs_deserialized: Proofs = serde_json::from_str(mint_proofs.value()).unwrap();
      proofs = mint_proofs_deserialized
    };

    Ok(proofs)
  }

  pub fn write_to_invalid_inputs_table(&mut self, v: Proof) -> Result<()> {
    let invalid_proof_serialized = serde_json::to_string(&v)?;
    let key = sha256_hasher(invalid_proof_serialized.as_bytes().to_vec());
    let key = hex::encode(key);

    let write_txn = self.begin_write()?;
    {
      let mut table = write_txn.open_table(Self::MINT_INVALID_INPUTS_TABLE)?;
      table.insert(key.as_str(), invalid_proof_serialized.as_str())?;
    }
    self.commit_txn(write_txn)?;
    Ok(())
  }

  pub fn get_invalid_input(&self, proof: Proof) -> Result<Option<Proof>> {
    let invalid_proof_serialized = serde_json::to_string(&proof)?;
    let key = sha256_hasher(invalid_proof_serialized.as_bytes().to_vec());
    let key = hex::encode(key);

    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::MINT_INVALID_INPUTS_TABLE)?;

    let response = table.get(key.as_str()).unwrap().map(|proof| {
      let proof_deserialized: Proof = serde_json::from_str(proof.value()).unwrap();
      proof_deserialized
    });

    Ok(response)
  }

  pub fn get_all_invalid_inputs(&self) -> Result<Proofs> {
    let mut proofs: Proofs = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::MINT_INVALID_INPUTS_TABLE)?;

    table.iter().unwrap().for_each(|proof| {
      let evt = proof.unwrap();
      let proof = evt.1.value();

      let proof_deserialized: Proof = serde_json::from_str(proof).unwrap();

      proofs.push(proof_deserialized);
    });

    Ok(proofs)
  }

  pub fn write_to_mint_quotes_table(&mut self, v: PostMintQuoteBolt11Response) -> Result<()> {
    let quote_id = v.clone().quote;
    let mint_quote_serialized = serde_json::to_string(&v)?;
    let write_txn = self.begin_write()?;
    {
      let mut table = write_txn.open_table(Self::MINT_QUOTES_TABLE)?;
      table.insert(quote_id.as_str(), mint_quote_serialized.as_str())?;
    }
    self.commit_txn(write_txn)?;
    Ok(())
  }

  pub fn get_mint_quote(&self, quote_id: String) -> Result<Option<PostMintQuoteBolt11Response>> {
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::MINT_QUOTES_TABLE)?;

    let response = table.get(quote_id.as_str()).unwrap().map(|mint_quote| {
      let mint_quote_deserialized: PostMintQuoteBolt11Response =
        serde_json::from_str(mint_quote.value()).unwrap();
      mint_quote_deserialized
    });

    Ok(response)
  }

  pub fn get_all_mint_quotes(&self) -> Result<Vec<PostMintQuoteBolt11Response>> {
    let mut mint_quotes: Vec<PostMintQuoteBolt11Response> = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::MINT_QUOTES_TABLE)?;

    table.iter().unwrap().for_each(|db_mint_quote| {
      let evt = db_mint_quote.unwrap();
      let mint_quote = evt.1.value();

      let mint_quote_deserialized: PostMintQuoteBolt11Response =
        serde_json::from_str(mint_quote).unwrap();

      mint_quotes.push(mint_quote_deserialized);
    });

    Ok(mint_quotes)
  }

  pub fn write_to_wallet_quotes_table(&mut self, quote_id: String, amount: Amount) -> Result<()> {
    let write_txn = self.begin_write()?;
    {
      let mut table = write_txn.open_table(Self::WALLET_QUOTES_TABLE)?;
      table.insert(quote_id.as_str(), amount.to_string().as_str())?;
    }
    self.commit_txn(write_txn)?;
    Ok(())
  }

  pub fn get_all_wallet_quotes(&self) -> Result<Vec<(String, Amount)>> {
    let mut wallet_quotes: Vec<(String, Amount)> = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(Self::WALLET_QUOTES_TABLE)?;

    table.iter().unwrap().for_each(|db_wallet_quote| {
      let evt = db_wallet_quote.unwrap();
      let quote_id = evt.0.value().to_string();
      let quote_amount: Amount = evt.1.value().parse().unwrap();

      wallet_quotes.push((quote_id, quote_amount));
    });

    Ok(wallet_quotes)
  }

  fn begin_write(&self) -> Result<WriteTransaction> {
    Ok(self.db.begin_write()?)
  }

  fn commit_txn(&self, write_txn: WriteTransaction) -> Result<()> {
    Ok(write_txn.commit()?)
  }

  fn initialise_db(db_type: DBType) -> Result<Self> {
    fs::create_dir_all("db/")?;

    match db_type {
      DBType::MINT => CashuDatabase::initialise_mint_db(DBType::MINT.into()),
      DBType::WALLET => CashuDatabase::initialise_mint_db(DBType::WALLET.into()),
    }
  }

  fn initialise_mint_db(db_name: &str) -> Result<Self> {
    let db = Database::create(format!("db/{}.redb", db_name))?;

    let write_txn = db.begin_write()?;
    write_txn.open_table(Self::MINT_KEYSETS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::MINT_KEYPAIRS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::MINT_INVALID_INPUTS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::MINT_QUOTES_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.commit()?;

    Ok(Self { db })
  }

  fn initialise_wallet_db(db_name: &str) -> Result<Self> {
    let db = Database::create(format!("db/{}.redb", db_name))?;

    let write_txn = db.begin_write()?;
    write_txn.open_table(Self::WALLET_PROOFS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::WALLET_QUOTES_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.commit()?;

    Ok(Self { db })
  }

  fn initialise_test_db(db_name: &str) -> Result<Self> {
    fs::create_dir_all("db/test/")?;
    let db = Database::create(format!("db/test/{}.redb", db_name))?;

    let write_txn = db.begin_write()?;
    write_txn.open_table(Self::MINT_KEYSETS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::MINT_KEYPAIRS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::WALLET_PROOFS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::MINT_INVALID_INPUTS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::MINT_QUOTES_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(Self::WALLET_QUOTES_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.commit()?;

    Ok(Self { db })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[cfg(test)]
  use serde_json::json;

  struct Sut {
    db: CashuDatabase,
    db_name: String,
  }

  impl Drop for Sut {
    fn drop(&mut self) {
      self.remove_temp_db();
    }
  }

  impl Sut {
    fn new(db_name: &str) -> Self {
      let db = CashuDatabase::new_testing_db(db_name).unwrap();

      Self {
        db,
        db_name: db_name.to_string(),
      }
    }

    fn gen_keyset(&self) -> KeysetWithKeys {
      let keyset = json!(
        {
          "id": "009a1f293253e41e",
          "unit": "sat",
          "active": true,
          "keys": {
              "1": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104",
              "2": "03b0f36d6d47ce14df8a7be9137712c42bcdd960b19dd02f1d4a9703b1f31d7513",
              "4": "0366be6e026e42852498efb82014ca91e89da2e7a5bd3761bdad699fa2aec9fe09",
              "8": "0253de5237f189606f29d8a690ea719f74d65f617bb1cb6fbea34f2bc4f930016d",
          }
        }
      );
      let keyset: KeysetWithKeys = serde_json::from_value(keyset).unwrap();
      keyset
    }

    fn gen_keypairs(&self) -> Keypairs {
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

    fn gen_invalid_proofs(&self) -> Proofs {
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

    fn gen_mint_quotes(&self) -> Vec<PostMintQuoteBolt11Response> {
      let quote1 = PostMintQuoteBolt11Response {
        expiry: 1714038710,
        quote: "f3091ac2-3ba7-442e-a330-2d12bf5d3a95".to_string(),
        paid: false,
        request: "ln1230940something".to_string(),
        amount: 1,
      };
      let quote2 = PostMintQuoteBolt11Response {
        expiry: 1814038710,
        quote: "e3091ac2-3ba7-442e-a330-2d12bf5d3a95".to_string(),
        paid: true,
        request: "ln2230940something".to_string(),
        amount: 2,
      };
      let quote3 = PostMintQuoteBolt11Response {
        expiry: 1914038710,
        quote: "d3091ac2-3ba7-442e-a330-2d12bf5d3a95".to_string(),
        paid: false,
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
  fn write_to_keysets_table() {
    let mut sut = Sut::new("write_to_keysets_table");
    let mock_keyset = sut.gen_keyset();

    let result = sut.db.get_all_keysets().unwrap();
    assert_eq!(result.len(), 0);

    sut
      .db
      .write_to_keysets_table("0", mock_keyset.clone())
      .unwrap();
    sut
      .db
      .write_to_keysets_table("1", mock_keyset.clone())
      .unwrap();
    sut.db.write_to_keysets_table("2", mock_keyset).unwrap();

    let result = sut.db.get_all_keysets().unwrap();
    assert_eq!(result.len(), 3);
  }

  #[test]
  fn write_to_keypairs_table() {
    let mut sut = Sut::new("write_to_keypairs_table");
    let mock_keypairs = sut.gen_keypairs();

    let result = sut.db.get_all_keypairs().unwrap();
    assert_eq!(result.len(), 0);

    sut
      .db
      .write_to_keypairs_table(mock_keypairs[0].pubkey, mock_keypairs[0].secretkey)
      .unwrap();
    sut
      .db
      .write_to_keypairs_table(mock_keypairs[0].pubkey, mock_keypairs[0].secretkey)
      .unwrap();
    sut
      .db
      .write_to_keypairs_table(mock_keypairs[0].pubkey, mock_keypairs[0].secretkey)
      .unwrap();

    let result = sut.db.get_all_keypairs().unwrap();
    assert_eq!(result.len(), 1); // when writing to the same key, it is updated

    sut
      .db
      .write_to_keypairs_table(mock_keypairs[1].pubkey, mock_keypairs[1].secretkey)
      .unwrap();
    sut
      .db
      .write_to_keypairs_table(mock_keypairs[2].pubkey, mock_keypairs[2].secretkey)
      .unwrap();

    let result = sut.db.get_all_keypairs().unwrap();
    assert_eq!(result.len(), 3);
  }

  #[test]
  fn write_to_invalid_inputs_table() {
    // arrange
    let mut sut = Sut::new("write_to_invalid_inputs_table");
    let mock_invalid_inputs = sut.gen_invalid_proofs();
    // act
    let result = sut.db.get_all_invalid_inputs().unwrap();
    assert_eq!(result.len(), 0);
    let _ = sut
      .db
      .write_to_invalid_inputs_table(mock_invalid_inputs[0].clone());
    let _ = sut
      .db
      .write_to_invalid_inputs_table(mock_invalid_inputs[1].clone());
    let _ = sut
      .db
      .write_to_invalid_inputs_table(mock_invalid_inputs[2].clone());

    let result = sut.db.get_all_invalid_inputs().unwrap();
    assert_eq!(result.len(), 3);

    let res = sut
      .db
      .get_invalid_input(mock_invalid_inputs[1].clone())
      .unwrap();
    assert_eq!(res, Some(mock_invalid_inputs[1].clone()));
  }

  #[test]
  fn write_to_mint_quotes_table() {
    // arrange
    let mut sut = Sut::new("write_to_mint_quotes_table");
    let mock_mint_quotes = sut.gen_mint_quotes();

    // act
    let result = sut.db.get_all_mint_quotes().unwrap();
    assert_eq!(result.len(), 0);
    let _ = sut
      .db
      .write_to_mint_quotes_table(mock_mint_quotes[0].clone());
    let _ = sut
      .db
      .write_to_mint_quotes_table(mock_mint_quotes[1].clone());
    let _ = sut
      .db
      .write_to_mint_quotes_table(mock_mint_quotes[2].clone());

    let result = sut.db.get_all_mint_quotes().unwrap();
    assert_eq!(result.len(), 3);

    let res = sut
      .db
      .get_mint_quote(mock_mint_quotes[1].clone().quote)
      .unwrap();
    assert_eq!(res, Some(mock_mint_quotes[1].clone()));
  }

  #[test]
  fn write_to_wallet_quotes_table() {
    // arrange
    let mut sut = Sut::new("write_to_wallet_quotes_table");
    let mock_quotes = [
      ("quote_id_0", 16u64),
      ("quote_id_1", 32u64),
      ("quote_id_2", 64u64),
    ];

    // act
    let result = sut.db.get_all_wallet_quotes().unwrap();
    assert_eq!(result.len(), 0);
    let _ = sut
      .db
      .write_to_wallet_quotes_table(mock_quotes[0].0.to_string(), mock_quotes[0].1);
    let _ = sut
      .db
      .write_to_wallet_quotes_table(mock_quotes[1].0.to_string(), mock_quotes[1].1);
    let _ = sut
      .db
      .write_to_wallet_quotes_table(mock_quotes[2].0.to_string(), mock_quotes[2].1);

    let result = sut.db.get_all_wallet_quotes().unwrap();
    assert_eq!(result.len(), 3);
  }

  #[test]
  fn write_to_wallet_proofs_table() {
    // arrange
    let mut sut = Sut::new("write_to_wallet_proofs_table");
    let mock_proofs = sut.gen_invalid_proofs();

    // act
    let result = sut.db.get_all_tokens().unwrap();
    assert_eq!(result.len(), 0);

    let mint_url0 = "mint0.com";
    let _ = sut
      .db
      .write_to_wallet_proofs_table(mint_url0, vec![mock_proofs[0].clone()]);
    let mint_url1 = "mint1.com";
    let _ = sut
      .db
      .write_to_wallet_proofs_table(mint_url1, vec![mock_proofs[1].clone()]);
    let mint_url2 = "mint2.com";
    let _ = sut
      .db
      .write_to_wallet_proofs_table(mint_url2, vec![mock_proofs[2].clone()]);

    let result = sut.db.get_all_tokens().unwrap();
    assert_eq!(result.len(), 3);

    let res = sut
      .db
      .get_all_proofs_from_mint(mint_url0.to_string())
      .unwrap();
    assert_eq!(res, vec![mock_proofs[0].clone()]);
  }

  #[test]
  fn get_all_keysets() {
    let sut = Sut::new("get_all_keysets");

    let result = sut.db.get_all_keysets().unwrap();

    assert_eq!(result.len(), 0);
  }

  #[test]
  fn get_all_keypairs() {
    let sut = Sut::new("get_all_keypairs");

    let result = sut.db.get_all_keypairs().unwrap();

    assert_eq!(result.len(), 0);
  }

  #[test]
  fn get_all_invalid_inputs() {
    let sut = Sut::new("get_all_invalid_inputs");

    let result = sut.db.get_all_invalid_inputs().unwrap();

    assert_eq!(result.len(), 0);
  }

  #[test]
  fn get_invalid_input() {
    let sut = Sut::new("get_invalid_input");
    let invalid_proofs = sut.gen_invalid_proofs();

    let result = sut.db.get_invalid_input(invalid_proofs[0].clone()).unwrap();

    assert!(result.is_none());
  }

  #[test]
  fn get_mint_quote() {
    let sut = Sut::new("get_mint_quote");
    let quote_id = "some-random=id".to_string();

    let result = sut.db.get_mint_quote(quote_id).unwrap();

    assert!(result.is_none());
  }

  #[test]
  fn get_all_mint_quotes() {
    let sut = Sut::new("get_all_mint_quotes");

    let result = sut.db.get_all_mint_quotes().unwrap();

    assert_eq!(result.len(), 0);
  }

  #[test]
  fn get_all_wallet_quotes() {
    let sut = Sut::new("get_all_wallet_quotes");

    let result = sut.db.get_all_wallet_quotes().unwrap();

    assert_eq!(result.len(), 0);
  }
}
