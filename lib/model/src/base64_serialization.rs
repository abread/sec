use serde::{Deserialize, Deserializer, Serializer};
use sodiumoxide::base64;
use sodiumoxide::crypto::{box_, sign};

pub(super) trait Base64SerializationExt {
    fn serialize<S>(data: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
        Self: Sized;
}

impl Base64SerializationExt for Vec<u8> {
    fn serialize<S>(data: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::encode(&data, base64::Variant::Original);
        serializer.serialize_str(&encoded)
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|encoded| {
            base64::decode(&encoded, base64::Variant::Original)
                .map_err(|_| Error::custom("base64 decode error"))
        })
    }
}

macro_rules! gen_impl_Base64SerializationExt {
    ($type:ty) => {
        impl Base64SerializationExt for $type {
            fn serialize<S>(key: &Self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let encoded = base64::encode(key.as_ref(), base64::Variant::Original);
                serializer.serialize_str(&encoded)
            }

            fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                use serde::de::Error;
                let bytes: Vec<u8> = Base64SerializationExt::deserialize(deserializer)?;

                Self::from_slice(&bytes).ok_or(Error::custom("key parse error"))
            }
        }
    };
}

gen_impl_Base64SerializationExt!(box_::PublicKey);
gen_impl_Base64SerializationExt!(box_::SecretKey);
gen_impl_Base64SerializationExt!(sign::PublicKey);
gen_impl_Base64SerializationExt!(sign::SecretKey);
