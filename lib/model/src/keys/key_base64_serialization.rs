use serde::{Deserialize, Deserializer, Serializer};
use sodiumoxide::base64;
use sodiumoxide::crypto::{box_, sign};

pub(super) trait KeyBase64SerializationExt: AsRef<[u8]> + Sized {
    fn serialize<S>(key: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&key.b64encode())
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|s| {
            KeyBase64SerializationExt::b64decode(&s).map_err(|e| Error::custom(e.to_owned()))
        })
    }

    fn b64encode(&self) -> String {
        base64::encode(self.as_ref(), base64::Variant::Original)
    }
    fn b64decode(serialized: &str) -> Result<Self, &'static str>
    where
        Self: Sized;
}

macro_rules! gen_impl_KeyBase64SerializationExt {
    ($type:ty) => {
        impl KeyBase64SerializationExt for $type {
            fn b64decode(encoded: &str) -> Result<Self, &'static str>
            where
                Self: Sized,
            {
                let decoded = base64::decode(encoded, base64::Variant::Original)
                    .map_err(|_| "base64 decode error")?;
                Self::from_slice(&decoded).ok_or("key parse error")
            }
        }
    };
}

gen_impl_KeyBase64SerializationExt!(box_::PublicKey);
gen_impl_KeyBase64SerializationExt!(box_::SecretKey);
gen_impl_KeyBase64SerializationExt!(sign::PublicKey);
gen_impl_KeyBase64SerializationExt!(sign::SecretKey);
