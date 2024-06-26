use serde::{Deserialize, Serialize};

use crate::types::Token;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CashuToken {
  token: Vec<Token>,
  /// optional currency unit of the token
  unit: Option<String>,
  /// optional text memo from the sender
  memo: Option<String>,
}
impl CashuToken {
  const PREFIX: &'static str = "cashu";
  const URI_PREFIX: &'static str = "cashu:";
  const VERSION: &'static str = "A";

  fn encode(&self, uri: Option<bool>) -> String {
    use base64::{engine::general_purpose::URL_SAFE, Engine as _};

    let json = serde_json::to_string(&self).unwrap_or_else(|_| String::new());
    let b64 = URL_SAFE.encode(json);

    if let Some(is_uri) = uri {
      if is_uri {
        return format!("{}{}{}{b64}", Self::URI_PREFIX, Self::PREFIX, Self::VERSION);
      }
    }

    format!("{}{}{b64}", Self::PREFIX, Self::VERSION)
  }

  pub fn decode(encoded: &str) -> Option<Self> {
    use base64::{engine::general_purpose::URL_SAFE, Engine as _};

    if encoded.starts_with(Self::URI_PREFIX) {
      let pat = format!("{}{}{}", Self::URI_PREFIX, Self::PREFIX, Self::VERSION);
      let b64 = encoded.trim_start_matches(&pat);
      let json = URL_SAFE.decode(b64).ok()?;
      serde_json::from_slice(&json).ok()
    } else if encoded.starts_with(Self::PREFIX) {
      let pat = format!("{}{}", Self::PREFIX, Self::VERSION);
      let b64 = encoded.trim_start_matches(&pat);
      let json = URL_SAFE.decode(b64).ok()?;
      serde_json::from_slice(&json).ok()
    } else {
      None
    }
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  #[test]
  fn token_encoding_decoding() {
    let example_json_token = json!(
      {
        "token": [
          {
            "mint": "https://8333.space:3338",
            "proofs": [
              {
                "amount": 2,
                "id": "009a1f293253e41e",
                "secret": "407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837",
                "C": "02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea"
              },
              {
                "amount": 8,
                "id": "009a1f293253e41e",
                "secret": "fe15109314e61d7756b0f8ee0f23a624acaa3f4e042f61433c728c7057b931be",
                "C": "029e8e5050b890a7d6c0968db16bc1d5d5fa040ea1de284f6ec69d61299f671059"
              }
            ]
          }
        ],
        "unit": "sat",
        "memo": "Thank you."
      }
    );
    let expected_serialized = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91LiJ9";
    let expected_serialized_uri = "cashu:cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91LiJ9";

    let decoded_token_from_json: CashuToken =
      serde_json::from_value(example_json_token).expect("decode json");

    let decoded_token_from_serialized =
      CashuToken::decode(expected_serialized).expect("decode cashutoken");
    assert_eq!(decoded_token_from_json, decoded_token_from_serialized);
    let decoded_token_from_serialized_uri =
      CashuToken::decode(expected_serialized_uri).expect("decode uri cashutoken");
    assert_eq!(decoded_token_from_json, decoded_token_from_serialized_uri);

    let serialized = decoded_token_from_serialized.encode(None);
    assert_eq!(expected_serialized, serialized);
    let serialized_uri = decoded_token_from_serialized.encode(Some(true));
    assert_eq!(expected_serialized_uri, serialized_uri);

    assert_eq!(
      CashuToken::decode(&decoded_token_from_json.encode(None)).expect("decode token round trip"),
      decoded_token_from_json
    );
    assert_eq!(
      CashuToken::decode(&decoded_token_from_json.encode(Some(true)))
        .expect("decode uri token round trip"),
      decoded_token_from_json
    );
  }
}
