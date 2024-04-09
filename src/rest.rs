use crate::keyset::{Keyset, KeysetWithKeys};

pub struct GetKeysResponse {
  keysets: KeysetWithKeys
}

pub struct GetKeysetsResponse {
  keysets: Vec<Keyset>
}