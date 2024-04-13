use bitcoin::secp256k1::{Error as Secp256k1Error, PublicKey, SecretKey};
use redb::{Database, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::{fs, result, str::FromStr};

use crate::{
  keyset::KeysetWithKeys,
  types::{Keypair, Keypairs},
};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, strum::Display, Serialize, Deserialize, Clone)]
pub enum MintDBTables {
  #[strum(serialize = "keysets")]
  KEYSETS,
}

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

// keyset_id, KeysetWithKeys
const KEYSETS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("keysets");

// pubkey, seckey
const KEYPAIRS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("keypairs");

type Result<T> = result::Result<T, CashuDatabaseError>;

pub struct MintDB {
  db: Database,
}

impl MintDB {
  pub fn new() -> Result<Self> {
    MintDB::initialise_db("mint")
  }

  fn new_testing_db(db_name: &str) -> Result<Self> {
    MintDB::initialise_db(db_name)
  }

  fn initialise_db(db_name: &str) -> Result<Self> {
    fs::create_dir_all("db/")?;
    let db = Database::create(format!("db/{}.redb", db_name))?;

    let write_txn = db.begin_write()?;
    write_txn.open_table(KEYSETS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.open_table(KEYPAIRS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.commit()?;

    Ok(Self { db })
  }

  pub fn write_to_keypairs_table(&mut self, k: PublicKey, v: SecretKey) -> Result<()> {
    let pubkey_serialized = hex::encode(k.serialize());
    let seckey_serialized = v.display_secret().to_string();
    let write_txn = self.begin_write()?;
    {
      let mut table = write_txn.open_table(KEYPAIRS_TABLE)?;
      table.insert(pubkey_serialized.as_str(), seckey_serialized.as_str())?;
    }
    self.commit_txn(write_txn)?;
    Ok(())
  }

  pub fn get_all_keypairs(&self) -> Result<Keypairs> {
    let mut keypairs: Keypairs = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(KEYPAIRS_TABLE)?;

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
      let mut table = write_txn.open_table(KEYSETS_TABLE)?;
      table.insert(k, value_serialized.as_str())?;
    }
    self.commit_txn(write_txn)?;
    Ok(())
  }

  pub fn get_all_keysets(&self) -> Result<Vec<KeysetWithKeys>> {
    let mut keysets: Vec<KeysetWithKeys> = vec![];
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(KEYSETS_TABLE)?;

    table.iter().unwrap().for_each(|keyset| {
      let evt = keyset.unwrap();
      let keyset_value = evt.1.value();
      let keyset_deserialized: KeysetWithKeys = serde_json::from_str(keyset_value).unwrap();
      keysets.push(keyset_deserialized);
    });

    Ok(keysets)
  }

  fn begin_write(&self) -> Result<WriteTransaction> {
    Ok(self.db.begin_write()?)
  }

  fn commit_txn(&self, write_txn: WriteTransaction) -> Result<()> {
    Ok(write_txn.commit()?)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(test)]
  use serde_json::json;

  struct Sut {
    db: MintDB,
    db_name: String,
  }

  impl Drop for Sut {
    fn drop(&mut self) {
      self.remove_temp_db();
    }
  }

  impl Sut {
    fn new(db_name: &str) -> Self {
      let db = MintDB::new_testing_db(db_name).unwrap();

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

    fn remove_temp_db(&self) {
      fs::remove_file(format!("db/{}.redb", self.db_name)).unwrap();
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
}