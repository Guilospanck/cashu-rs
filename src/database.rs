use redb::{Database, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::{fs, result};

use crate::keyset::KeysetWithKeys;

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
}

// id, KeysetWithKeys
const KEYSETS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("keysets");

type Result<T> = result::Result<T, CashuDatabaseError>;

pub struct MintDB {
  db: Database,
}

impl MintDB {
  pub fn new() -> Result<Self> {
    fs::create_dir_all("db/")?;
    let db = Database::create("db/mint.redb")?;

    let write_txn = db.begin_write()?;
    write_txn.open_table(KEYSETS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.commit()?;

    Ok(Self { db })
  }

  fn new_testing_db(db_name: &str) -> Result<Self> {
    fs::create_dir_all("db/")?;
    let db = Database::create(format!("db/{}.redb", db_name))?;

    let write_txn = db.begin_write()?;
    write_txn.open_table(KEYSETS_TABLE)?; // this basically just creates the table if doesn't exist
    write_txn.commit()?;

    Ok(Self { db })
  }

  pub fn write_to_keysets_table(&mut self, k: &str, v: KeysetWithKeys) -> Result<()> {
    let value_serialized = serde_json::to_string(&v)?;
    let write_txn = self.begin_write()?;
    {
      let mut table = write_txn.open_table(KEYSETS_TABLE)?;
      table.insert(k, &*value_serialized)?;
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

    fn remove_temp_db(&self) {
      fs::remove_file(format!("db/{}.redb", self.db_name)).unwrap();
    }
  }

  #[test]
  fn write_to_db() {
    let mut sut = Sut::new("write_to_db");
    let mock_keyset = sut.gen_keyset();

    let result = sut.db.get_all_keysets().unwrap();
    assert_eq!(result.len(), 0);

    sut.db.write_to_keysets_table("0", mock_keyset.clone()).unwrap();
    sut.db.write_to_keysets_table("1", mock_keyset.clone()).unwrap();
    sut.db.write_to_keysets_table("2", mock_keyset).unwrap();

    let result = sut.db.get_all_keysets().unwrap();
    assert_eq!(result.len(), 3);
  }

  #[test]
  fn get_all_keysets() {
    let sut = Sut::new("get_all_keysets");

    let result = sut.db.get_all_keysets().unwrap();

    assert_eq!(result.len(), 0);
  }
}
