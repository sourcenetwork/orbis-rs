use serde::Deserialize;

/// Transaction receipt from JSON-RPC eth_getTransactionReceipt
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct TransactionReceipt {
    /// Status: 0x1 for success, 0x0 for failure
    pub status: String,
    /// Transaction hash
    pub transaction_hash: String,
    /// Block number (hex)
    pub block_number: Option<String>,
    /// Gas used (hex)
    pub gas_used: Option<String>,
}

impl TransactionReceipt {
    pub fn succeeded(&self) -> bool {
        self.status == "0x1"
    }
}

/// Post structure matching hub.rs bulletin module JSON output.
///
/// Hub.rs may return `payload` and `proof` as either a base64 string
/// or a JSON byte array (e.g. `[123, 34, ...]`). The custom deserializer
/// handles both formats, storing the raw bytes.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct HubPost {
    pub id: String,
    pub namespace: String,
    #[serde(default)]
    pub creator_did: String,
    #[serde(deserialize_with = "deserialize_bytes_or_string")]
    pub payload: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_bytes_or_string_opt")]
    pub proof: Vec<u8>,
}

fn deserialize_bytes_or_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct BytesOrString;

    impl<'de> de::Visitor<'de> for BytesOrString {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or byte array")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(v)
                .unwrap_or_else(|_| v.as_bytes().to_vec())
                .pipe(Ok)
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::new();
            while let Some(b) = seq.next_element::<u8>()? {
                bytes.push(b);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_any(BytesOrString)
}

fn deserialize_bytes_or_string_opt<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bytes_or_string(deserializer)
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}
