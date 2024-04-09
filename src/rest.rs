use crate::keyset::{Keyset, KeysetWithKeys};

pub struct GetKeysResponse {
  pub keysets: Vec<KeysetWithKeys>
}

pub struct GetKeysetsResponse {
  pub keysets: Vec<Keyset>
}