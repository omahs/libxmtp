// @generated
impl serde::Serialize for Ciphertext {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.union.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.Ciphertext", len)?;
        if let Some(v) = self.union.as_ref() {
            match v {
                ciphertext::Union::Aes256GcmHkdfSha256(v) => {
                    struct_ser.serialize_field("aes256GcmHkdfSha256", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Ciphertext {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "aes256_gcm_hkdf_sha256",
            "aes256GcmHkdfSha256",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Aes256GcmHkdfSha256,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "aes256GcmHkdfSha256" | "aes256_gcm_hkdf_sha256" => Ok(GeneratedField::Aes256GcmHkdfSha256),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Ciphertext;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.Ciphertext")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<Ciphertext, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut union__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Aes256GcmHkdfSha256 => {
                            if union__.is_some() {
                                return Err(serde::de::Error::duplicate_field("aes256GcmHkdfSha256"));
                            }
                            union__ = map.next_value::<::std::option::Option<_>>()?.map(ciphertext::Union::Aes256GcmHkdfSha256)
;
                        }
                    }
                }
                Ok(Ciphertext {
                    union: union__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.Ciphertext", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ciphertext::Aes256gcmHkdfsha256 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.hkdf_salt.is_empty() {
            len += 1;
        }
        if !self.gcm_nonce.is_empty() {
            len += 1;
        }
        if !self.payload.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.Ciphertext.Aes256gcmHkdfsha256", len)?;
        if !self.hkdf_salt.is_empty() {
            struct_ser.serialize_field("hkdfSalt", pbjson::private::base64::encode(&self.hkdf_salt).as_str())?;
        }
        if !self.gcm_nonce.is_empty() {
            struct_ser.serialize_field("gcmNonce", pbjson::private::base64::encode(&self.gcm_nonce).as_str())?;
        }
        if !self.payload.is_empty() {
            struct_ser.serialize_field("payload", pbjson::private::base64::encode(&self.payload).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ciphertext::Aes256gcmHkdfsha256 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "hkdf_salt",
            "hkdfSalt",
            "gcm_nonce",
            "gcmNonce",
            "payload",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            HkdfSalt,
            GcmNonce,
            Payload,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "hkdfSalt" | "hkdf_salt" => Ok(GeneratedField::HkdfSalt),
                            "gcmNonce" | "gcm_nonce" => Ok(GeneratedField::GcmNonce),
                            "payload" => Ok(GeneratedField::Payload),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ciphertext::Aes256gcmHkdfsha256;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.Ciphertext.Aes256gcmHkdfsha256")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ciphertext::Aes256gcmHkdfsha256, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut hkdf_salt__ = None;
                let mut gcm_nonce__ = None;
                let mut payload__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::HkdfSalt => {
                            if hkdf_salt__.is_some() {
                                return Err(serde::de::Error::duplicate_field("hkdfSalt"));
                            }
                            hkdf_salt__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::GcmNonce => {
                            if gcm_nonce__.is_some() {
                                return Err(serde::de::Error::duplicate_field("gcmNonce"));
                            }
                            gcm_nonce__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Payload => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("payload"));
                            }
                            payload__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(ciphertext::Aes256gcmHkdfsha256 {
                    hkdf_salt: hkdf_salt__.unwrap_or_default(),
                    gcm_nonce: gcm_nonce__.unwrap_or_default(),
                    payload: payload__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.Ciphertext.Aes256gcmHkdfsha256", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Composite {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.parts.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.Composite", len)?;
        if !self.parts.is_empty() {
            struct_ser.serialize_field("parts", &self.parts)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Composite {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "parts",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Parts,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "parts" => Ok(GeneratedField::Parts),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Composite;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.Composite")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<Composite, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut parts__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Parts => {
                            if parts__.is_some() {
                                return Err(serde::de::Error::duplicate_field("parts"));
                            }
                            parts__ = Some(map.next_value()?);
                        }
                    }
                }
                Ok(Composite {
                    parts: parts__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.Composite", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for composite::Part {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.element.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.Composite.Part", len)?;
        if let Some(v) = self.element.as_ref() {
            match v {
                composite::part::Element::Part(v) => {
                    struct_ser.serialize_field("part", v)?;
                }
                composite::part::Element::Composite(v) => {
                    struct_ser.serialize_field("composite", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for composite::Part {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "part",
            "composite",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Part,
            Composite,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "part" => Ok(GeneratedField::Part),
                            "composite" => Ok(GeneratedField::Composite),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = composite::Part;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.Composite.Part")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<composite::Part, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut element__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Part => {
                            if element__.is_some() {
                                return Err(serde::de::Error::duplicate_field("part"));
                            }
                            element__ = map.next_value::<::std::option::Option<_>>()?.map(composite::part::Element::Part)
;
                        }
                        GeneratedField::Composite => {
                            if element__.is_some() {
                                return Err(serde::de::Error::duplicate_field("composite"));
                            }
                            element__ = map.next_value::<::std::option::Option<_>>()?.map(composite::part::Element::Composite)
;
                        }
                    }
                }
                Ok(composite::Part {
                    element: element__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.Composite.Part", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Compression {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Deflate => "COMPRESSION_DEFLATE",
            Self::Gzip => "COMPRESSION_GZIP",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for Compression {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "COMPRESSION_DEFLATE",
            "COMPRESSION_GZIP",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Compression;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use std::convert::TryFrom;
                i32::try_from(v)
                    .ok()
                    .and_then(Compression::from_i32)
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use std::convert::TryFrom;
                i32::try_from(v)
                    .ok()
                    .and_then(Compression::from_i32)
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "COMPRESSION_DEFLATE" => Ok(Compression::Deflate),
                    "COMPRESSION_GZIP" => Ok(Compression::Gzip),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for ContactBundle {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.version.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.ContactBundle", len)?;
        if let Some(v) = self.version.as_ref() {
            match v {
                contact_bundle::Version::V1(v) => {
                    struct_ser.serialize_field("v1", v)?;
                }
                contact_bundle::Version::V2(v) => {
                    struct_ser.serialize_field("v2", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ContactBundle {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "v1",
            "v2",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            V1,
            V2,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "v1" => Ok(GeneratedField::V1),
                            "v2" => Ok(GeneratedField::V2),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ContactBundle;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.ContactBundle")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ContactBundle, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut version__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::V1 => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("v1"));
                            }
                            version__ = map.next_value::<::std::option::Option<_>>()?.map(contact_bundle::Version::V1)
;
                        }
                        GeneratedField::V2 => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("v2"));
                            }
                            version__ = map.next_value::<::std::option::Option<_>>()?.map(contact_bundle::Version::V2)
;
                        }
                    }
                }
                Ok(ContactBundle {
                    version: version__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.ContactBundle", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ContactBundleV1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.key_bundle.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.ContactBundleV1", len)?;
        if let Some(v) = self.key_bundle.as_ref() {
            struct_ser.serialize_field("keyBundle", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ContactBundleV1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "key_bundle",
            "keyBundle",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            KeyBundle,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "keyBundle" | "key_bundle" => Ok(GeneratedField::KeyBundle),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ContactBundleV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.ContactBundleV1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ContactBundleV1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut key_bundle__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::KeyBundle => {
                            if key_bundle__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keyBundle"));
                            }
                            key_bundle__ = map.next_value()?;
                        }
                    }
                }
                Ok(ContactBundleV1 {
                    key_bundle: key_bundle__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.ContactBundleV1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ContactBundleV2 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.key_bundle.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.ContactBundleV2", len)?;
        if let Some(v) = self.key_bundle.as_ref() {
            struct_ser.serialize_field("keyBundle", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ContactBundleV2 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "key_bundle",
            "keyBundle",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            KeyBundle,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "keyBundle" | "key_bundle" => Ok(GeneratedField::KeyBundle),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ContactBundleV2;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.ContactBundleV2")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ContactBundleV2, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut key_bundle__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::KeyBundle => {
                            if key_bundle__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keyBundle"));
                            }
                            key_bundle__ = map.next_value()?;
                        }
                    }
                }
                Ok(ContactBundleV2 {
                    key_bundle: key_bundle__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.ContactBundleV2", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ContentTypeId {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.authority_id.is_empty() {
            len += 1;
        }
        if !self.type_id.is_empty() {
            len += 1;
        }
        if self.version_major != 0 {
            len += 1;
        }
        if self.version_minor != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.ContentTypeId", len)?;
        if !self.authority_id.is_empty() {
            struct_ser.serialize_field("authorityId", &self.authority_id)?;
        }
        if !self.type_id.is_empty() {
            struct_ser.serialize_field("typeId", &self.type_id)?;
        }
        if self.version_major != 0 {
            struct_ser.serialize_field("versionMajor", &self.version_major)?;
        }
        if self.version_minor != 0 {
            struct_ser.serialize_field("versionMinor", &self.version_minor)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ContentTypeId {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "authority_id",
            "authorityId",
            "type_id",
            "typeId",
            "version_major",
            "versionMajor",
            "version_minor",
            "versionMinor",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            AuthorityId,
            TypeId,
            VersionMajor,
            VersionMinor,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "authorityId" | "authority_id" => Ok(GeneratedField::AuthorityId),
                            "typeId" | "type_id" => Ok(GeneratedField::TypeId),
                            "versionMajor" | "version_major" => Ok(GeneratedField::VersionMajor),
                            "versionMinor" | "version_minor" => Ok(GeneratedField::VersionMinor),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ContentTypeId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.ContentTypeId")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ContentTypeId, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut authority_id__ = None;
                let mut type_id__ = None;
                let mut version_major__ = None;
                let mut version_minor__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::AuthorityId => {
                            if authority_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("authorityId"));
                            }
                            authority_id__ = Some(map.next_value()?);
                        }
                        GeneratedField::TypeId => {
                            if type_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("typeId"));
                            }
                            type_id__ = Some(map.next_value()?);
                        }
                        GeneratedField::VersionMajor => {
                            if version_major__.is_some() {
                                return Err(serde::de::Error::duplicate_field("versionMajor"));
                            }
                            version_major__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::VersionMinor => {
                            if version_minor__.is_some() {
                                return Err(serde::de::Error::duplicate_field("versionMinor"));
                            }
                            version_minor__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(ContentTypeId {
                    authority_id: authority_id__.unwrap_or_default(),
                    type_id: type_id__.unwrap_or_default(),
                    version_major: version_major__.unwrap_or_default(),
                    version_minor: version_minor__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.ContentTypeId", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ConversationReference {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.topic.is_empty() {
            len += 1;
        }
        if !self.peer_address.is_empty() {
            len += 1;
        }
        if self.created_ns != 0 {
            len += 1;
        }
        if self.context.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.ConversationReference", len)?;
        if !self.topic.is_empty() {
            struct_ser.serialize_field("topic", &self.topic)?;
        }
        if !self.peer_address.is_empty() {
            struct_ser.serialize_field("peerAddress", &self.peer_address)?;
        }
        if self.created_ns != 0 {
            struct_ser.serialize_field("createdNs", ToString::to_string(&self.created_ns).as_str())?;
        }
        if let Some(v) = self.context.as_ref() {
            struct_ser.serialize_field("context", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ConversationReference {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "topic",
            "peer_address",
            "peerAddress",
            "created_ns",
            "createdNs",
            "context",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Topic,
            PeerAddress,
            CreatedNs,
            Context,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "topic" => Ok(GeneratedField::Topic),
                            "peerAddress" | "peer_address" => Ok(GeneratedField::PeerAddress),
                            "createdNs" | "created_ns" => Ok(GeneratedField::CreatedNs),
                            "context" => Ok(GeneratedField::Context),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ConversationReference;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.ConversationReference")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ConversationReference, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut topic__ = None;
                let mut peer_address__ = None;
                let mut created_ns__ = None;
                let mut context__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Topic => {
                            if topic__.is_some() {
                                return Err(serde::de::Error::duplicate_field("topic"));
                            }
                            topic__ = Some(map.next_value()?);
                        }
                        GeneratedField::PeerAddress => {
                            if peer_address__.is_some() {
                                return Err(serde::de::Error::duplicate_field("peerAddress"));
                            }
                            peer_address__ = Some(map.next_value()?);
                        }
                        GeneratedField::CreatedNs => {
                            if created_ns__.is_some() {
                                return Err(serde::de::Error::duplicate_field("createdNs"));
                            }
                            created_ns__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Context => {
                            if context__.is_some() {
                                return Err(serde::de::Error::duplicate_field("context"));
                            }
                            context__ = map.next_value()?;
                        }
                    }
                }
                Ok(ConversationReference {
                    topic: topic__.unwrap_or_default(),
                    peer_address: peer_address__.unwrap_or_default(),
                    created_ns: created_ns__.unwrap_or_default(),
                    context: context__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.ConversationReference", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for DecodedMessage {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.id.is_empty() {
            len += 1;
        }
        if !self.message_version.is_empty() {
            len += 1;
        }
        if !self.sender_address.is_empty() {
            len += 1;
        }
        if self.recipient_address.is_some() {
            len += 1;
        }
        if self.sent_ns != 0 {
            len += 1;
        }
        if !self.content_topic.is_empty() {
            len += 1;
        }
        if self.conversation.is_some() {
            len += 1;
        }
        if !self.content_bytes.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.DecodedMessage", len)?;
        if !self.id.is_empty() {
            struct_ser.serialize_field("id", &self.id)?;
        }
        if !self.message_version.is_empty() {
            struct_ser.serialize_field("messageVersion", &self.message_version)?;
        }
        if !self.sender_address.is_empty() {
            struct_ser.serialize_field("senderAddress", &self.sender_address)?;
        }
        if let Some(v) = self.recipient_address.as_ref() {
            struct_ser.serialize_field("recipientAddress", v)?;
        }
        if self.sent_ns != 0 {
            struct_ser.serialize_field("sentNs", ToString::to_string(&self.sent_ns).as_str())?;
        }
        if !self.content_topic.is_empty() {
            struct_ser.serialize_field("contentTopic", &self.content_topic)?;
        }
        if let Some(v) = self.conversation.as_ref() {
            struct_ser.serialize_field("conversation", v)?;
        }
        if !self.content_bytes.is_empty() {
            struct_ser.serialize_field("contentBytes", pbjson::private::base64::encode(&self.content_bytes).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for DecodedMessage {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "id",
            "message_version",
            "messageVersion",
            "sender_address",
            "senderAddress",
            "recipient_address",
            "recipientAddress",
            "sent_ns",
            "sentNs",
            "content_topic",
            "contentTopic",
            "conversation",
            "content_bytes",
            "contentBytes",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Id,
            MessageVersion,
            SenderAddress,
            RecipientAddress,
            SentNs,
            ContentTopic,
            Conversation,
            ContentBytes,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "id" => Ok(GeneratedField::Id),
                            "messageVersion" | "message_version" => Ok(GeneratedField::MessageVersion),
                            "senderAddress" | "sender_address" => Ok(GeneratedField::SenderAddress),
                            "recipientAddress" | "recipient_address" => Ok(GeneratedField::RecipientAddress),
                            "sentNs" | "sent_ns" => Ok(GeneratedField::SentNs),
                            "contentTopic" | "content_topic" => Ok(GeneratedField::ContentTopic),
                            "conversation" => Ok(GeneratedField::Conversation),
                            "contentBytes" | "content_bytes" => Ok(GeneratedField::ContentBytes),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = DecodedMessage;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.DecodedMessage")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<DecodedMessage, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut id__ = None;
                let mut message_version__ = None;
                let mut sender_address__ = None;
                let mut recipient_address__ = None;
                let mut sent_ns__ = None;
                let mut content_topic__ = None;
                let mut conversation__ = None;
                let mut content_bytes__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Id => {
                            if id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("id"));
                            }
                            id__ = Some(map.next_value()?);
                        }
                        GeneratedField::MessageVersion => {
                            if message_version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("messageVersion"));
                            }
                            message_version__ = Some(map.next_value()?);
                        }
                        GeneratedField::SenderAddress => {
                            if sender_address__.is_some() {
                                return Err(serde::de::Error::duplicate_field("senderAddress"));
                            }
                            sender_address__ = Some(map.next_value()?);
                        }
                        GeneratedField::RecipientAddress => {
                            if recipient_address__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recipientAddress"));
                            }
                            recipient_address__ = map.next_value()?;
                        }
                        GeneratedField::SentNs => {
                            if sent_ns__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sentNs"));
                            }
                            sent_ns__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::ContentTopic => {
                            if content_topic__.is_some() {
                                return Err(serde::de::Error::duplicate_field("contentTopic"));
                            }
                            content_topic__ = Some(map.next_value()?);
                        }
                        GeneratedField::Conversation => {
                            if conversation__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversation"));
                            }
                            conversation__ = map.next_value()?;
                        }
                        GeneratedField::ContentBytes => {
                            if content_bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("contentBytes"));
                            }
                            content_bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(DecodedMessage {
                    id: id__.unwrap_or_default(),
                    message_version: message_version__.unwrap_or_default(),
                    sender_address: sender_address__.unwrap_or_default(),
                    recipient_address: recipient_address__,
                    sent_ns: sent_ns__.unwrap_or_default(),
                    content_topic: content_topic__.unwrap_or_default(),
                    conversation: conversation__,
                    content_bytes: content_bytes__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.DecodedMessage", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for EncodedContent {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.r#type.is_some() {
            len += 1;
        }
        if !self.parameters.is_empty() {
            len += 1;
        }
        if self.fallback.is_some() {
            len += 1;
        }
        if self.compression.is_some() {
            len += 1;
        }
        if !self.content.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.EncodedContent", len)?;
        if let Some(v) = self.r#type.as_ref() {
            struct_ser.serialize_field("type", v)?;
        }
        if !self.parameters.is_empty() {
            struct_ser.serialize_field("parameters", &self.parameters)?;
        }
        if let Some(v) = self.fallback.as_ref() {
            struct_ser.serialize_field("fallback", v)?;
        }
        if let Some(v) = self.compression.as_ref() {
            let v = Compression::from_i32(*v)
                .ok_or_else(|| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
            struct_ser.serialize_field("compression", &v)?;
        }
        if !self.content.is_empty() {
            struct_ser.serialize_field("content", pbjson::private::base64::encode(&self.content).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for EncodedContent {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "type",
            "parameters",
            "fallback",
            "compression",
            "content",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Type,
            Parameters,
            Fallback,
            Compression,
            Content,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "type" => Ok(GeneratedField::Type),
                            "parameters" => Ok(GeneratedField::Parameters),
                            "fallback" => Ok(GeneratedField::Fallback),
                            "compression" => Ok(GeneratedField::Compression),
                            "content" => Ok(GeneratedField::Content),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = EncodedContent;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.EncodedContent")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<EncodedContent, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut r#type__ = None;
                let mut parameters__ = None;
                let mut fallback__ = None;
                let mut compression__ = None;
                let mut content__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Type => {
                            if r#type__.is_some() {
                                return Err(serde::de::Error::duplicate_field("type"));
                            }
                            r#type__ = map.next_value()?;
                        }
                        GeneratedField::Parameters => {
                            if parameters__.is_some() {
                                return Err(serde::de::Error::duplicate_field("parameters"));
                            }
                            parameters__ = Some(
                                map.next_value::<std::collections::HashMap<_, _>>()?
                            );
                        }
                        GeneratedField::Fallback => {
                            if fallback__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fallback"));
                            }
                            fallback__ = map.next_value()?;
                        }
                        GeneratedField::Compression => {
                            if compression__.is_some() {
                                return Err(serde::de::Error::duplicate_field("compression"));
                            }
                            compression__ = map.next_value::<::std::option::Option<Compression>>()?.map(|x| x as i32);
                        }
                        GeneratedField::Content => {
                            if content__.is_some() {
                                return Err(serde::de::Error::duplicate_field("content"));
                            }
                            content__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(EncodedContent {
                    r#type: r#type__,
                    parameters: parameters__.unwrap_or_default(),
                    fallback: fallback__,
                    compression: compression__,
                    content: content__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.EncodedContent", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for EncryptedPrivateKeyBundle {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.version.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.EncryptedPrivateKeyBundle", len)?;
        if let Some(v) = self.version.as_ref() {
            match v {
                encrypted_private_key_bundle::Version::V1(v) => {
                    struct_ser.serialize_field("v1", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for EncryptedPrivateKeyBundle {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "v1",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            V1,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "v1" => Ok(GeneratedField::V1),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = EncryptedPrivateKeyBundle;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.EncryptedPrivateKeyBundle")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<EncryptedPrivateKeyBundle, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut version__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::V1 => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("v1"));
                            }
                            version__ = map.next_value::<::std::option::Option<_>>()?.map(encrypted_private_key_bundle::Version::V1)
;
                        }
                    }
                }
                Ok(EncryptedPrivateKeyBundle {
                    version: version__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.EncryptedPrivateKeyBundle", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for EncryptedPrivateKeyBundleV1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.wallet_pre_key.is_empty() {
            len += 1;
        }
        if self.ciphertext.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.EncryptedPrivateKeyBundleV1", len)?;
        if !self.wallet_pre_key.is_empty() {
            struct_ser.serialize_field("walletPreKey", pbjson::private::base64::encode(&self.wallet_pre_key).as_str())?;
        }
        if let Some(v) = self.ciphertext.as_ref() {
            struct_ser.serialize_field("ciphertext", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for EncryptedPrivateKeyBundleV1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "wallet_pre_key",
            "walletPreKey",
            "ciphertext",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            WalletPreKey,
            Ciphertext,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "walletPreKey" | "wallet_pre_key" => Ok(GeneratedField::WalletPreKey),
                            "ciphertext" => Ok(GeneratedField::Ciphertext),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = EncryptedPrivateKeyBundleV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.EncryptedPrivateKeyBundleV1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<EncryptedPrivateKeyBundleV1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut wallet_pre_key__ = None;
                let mut ciphertext__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::WalletPreKey => {
                            if wallet_pre_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("walletPreKey"));
                            }
                            wallet_pre_key__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Ciphertext => {
                            if ciphertext__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ciphertext"));
                            }
                            ciphertext__ = map.next_value()?;
                        }
                    }
                }
                Ok(EncryptedPrivateKeyBundleV1 {
                    wallet_pre_key: wallet_pre_key__.unwrap_or_default(),
                    ciphertext: ciphertext__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.EncryptedPrivateKeyBundleV1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for InvitationV1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.topic.is_empty() {
            len += 1;
        }
        if self.context.is_some() {
            len += 1;
        }
        if self.encryption.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.InvitationV1", len)?;
        if !self.topic.is_empty() {
            struct_ser.serialize_field("topic", &self.topic)?;
        }
        if let Some(v) = self.context.as_ref() {
            struct_ser.serialize_field("context", v)?;
        }
        if let Some(v) = self.encryption.as_ref() {
            match v {
                invitation_v1::Encryption::Aes256GcmHkdfSha256(v) => {
                    struct_ser.serialize_field("aes256GcmHkdfSha256", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for InvitationV1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "topic",
            "context",
            "aes256_gcm_hkdf_sha256",
            "aes256GcmHkdfSha256",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Topic,
            Context,
            Aes256GcmHkdfSha256,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "topic" => Ok(GeneratedField::Topic),
                            "context" => Ok(GeneratedField::Context),
                            "aes256GcmHkdfSha256" | "aes256_gcm_hkdf_sha256" => Ok(GeneratedField::Aes256GcmHkdfSha256),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = InvitationV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.InvitationV1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<InvitationV1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut topic__ = None;
                let mut context__ = None;
                let mut encryption__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Topic => {
                            if topic__.is_some() {
                                return Err(serde::de::Error::duplicate_field("topic"));
                            }
                            topic__ = Some(map.next_value()?);
                        }
                        GeneratedField::Context => {
                            if context__.is_some() {
                                return Err(serde::de::Error::duplicate_field("context"));
                            }
                            context__ = map.next_value()?;
                        }
                        GeneratedField::Aes256GcmHkdfSha256 => {
                            if encryption__.is_some() {
                                return Err(serde::de::Error::duplicate_field("aes256GcmHkdfSha256"));
                            }
                            encryption__ = map.next_value::<::std::option::Option<_>>()?.map(invitation_v1::Encryption::Aes256GcmHkdfSha256)
;
                        }
                    }
                }
                Ok(InvitationV1 {
                    topic: topic__.unwrap_or_default(),
                    context: context__,
                    encryption: encryption__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.InvitationV1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for invitation_v1::Aes256gcmHkdfsha256 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.key_material.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.InvitationV1.Aes256gcmHkdfsha256", len)?;
        if !self.key_material.is_empty() {
            struct_ser.serialize_field("keyMaterial", pbjson::private::base64::encode(&self.key_material).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for invitation_v1::Aes256gcmHkdfsha256 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "key_material",
            "keyMaterial",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            KeyMaterial,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "keyMaterial" | "key_material" => Ok(GeneratedField::KeyMaterial),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = invitation_v1::Aes256gcmHkdfsha256;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.InvitationV1.Aes256gcmHkdfsha256")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<invitation_v1::Aes256gcmHkdfsha256, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut key_material__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::KeyMaterial => {
                            if key_material__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keyMaterial"));
                            }
                            key_material__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(invitation_v1::Aes256gcmHkdfsha256 {
                    key_material: key_material__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.InvitationV1.Aes256gcmHkdfsha256", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for invitation_v1::Context {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.conversation_id.is_empty() {
            len += 1;
        }
        if !self.metadata.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.InvitationV1.Context", len)?;
        if !self.conversation_id.is_empty() {
            struct_ser.serialize_field("conversationId", &self.conversation_id)?;
        }
        if !self.metadata.is_empty() {
            struct_ser.serialize_field("metadata", &self.metadata)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for invitation_v1::Context {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "conversation_id",
            "conversationId",
            "metadata",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            ConversationId,
            Metadata,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "conversationId" | "conversation_id" => Ok(GeneratedField::ConversationId),
                            "metadata" => Ok(GeneratedField::Metadata),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = invitation_v1::Context;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.InvitationV1.Context")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<invitation_v1::Context, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut conversation_id__ = None;
                let mut metadata__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::ConversationId => {
                            if conversation_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("conversationId"));
                            }
                            conversation_id__ = Some(map.next_value()?);
                        }
                        GeneratedField::Metadata => {
                            if metadata__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            metadata__ = Some(
                                map.next_value::<std::collections::HashMap<_, _>>()?
                            );
                        }
                    }
                }
                Ok(invitation_v1::Context {
                    conversation_id: conversation_id__.unwrap_or_default(),
                    metadata: metadata__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.InvitationV1.Context", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Message {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.version.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.Message", len)?;
        if let Some(v) = self.version.as_ref() {
            match v {
                message::Version::V1(v) => {
                    struct_ser.serialize_field("v1", v)?;
                }
                message::Version::V2(v) => {
                    struct_ser.serialize_field("v2", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Message {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "v1",
            "v2",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            V1,
            V2,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "v1" => Ok(GeneratedField::V1),
                            "v2" => Ok(GeneratedField::V2),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Message;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.Message")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<Message, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut version__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::V1 => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("v1"));
                            }
                            version__ = map.next_value::<::std::option::Option<_>>()?.map(message::Version::V1)
;
                        }
                        GeneratedField::V2 => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("v2"));
                            }
                            version__ = map.next_value::<::std::option::Option<_>>()?.map(message::Version::V2)
;
                        }
                    }
                }
                Ok(Message {
                    version: version__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.Message", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MessageHeaderV1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.sender.is_some() {
            len += 1;
        }
        if self.recipient.is_some() {
            len += 1;
        }
        if self.timestamp != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.MessageHeaderV1", len)?;
        if let Some(v) = self.sender.as_ref() {
            struct_ser.serialize_field("sender", v)?;
        }
        if let Some(v) = self.recipient.as_ref() {
            struct_ser.serialize_field("recipient", v)?;
        }
        if self.timestamp != 0 {
            struct_ser.serialize_field("timestamp", ToString::to_string(&self.timestamp).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MessageHeaderV1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "sender",
            "recipient",
            "timestamp",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Sender,
            Recipient,
            Timestamp,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "sender" => Ok(GeneratedField::Sender),
                            "recipient" => Ok(GeneratedField::Recipient),
                            "timestamp" => Ok(GeneratedField::Timestamp),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MessageHeaderV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.MessageHeaderV1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<MessageHeaderV1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut sender__ = None;
                let mut recipient__ = None;
                let mut timestamp__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Sender => {
                            if sender__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sender"));
                            }
                            sender__ = map.next_value()?;
                        }
                        GeneratedField::Recipient => {
                            if recipient__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recipient"));
                            }
                            recipient__ = map.next_value()?;
                        }
                        GeneratedField::Timestamp => {
                            if timestamp__.is_some() {
                                return Err(serde::de::Error::duplicate_field("timestamp"));
                            }
                            timestamp__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(MessageHeaderV1 {
                    sender: sender__,
                    recipient: recipient__,
                    timestamp: timestamp__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.MessageHeaderV1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MessageHeaderV2 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.created_ns != 0 {
            len += 1;
        }
        if !self.topic.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.MessageHeaderV2", len)?;
        if self.created_ns != 0 {
            struct_ser.serialize_field("createdNs", ToString::to_string(&self.created_ns).as_str())?;
        }
        if !self.topic.is_empty() {
            struct_ser.serialize_field("topic", &self.topic)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MessageHeaderV2 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "created_ns",
            "createdNs",
            "topic",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            CreatedNs,
            Topic,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "createdNs" | "created_ns" => Ok(GeneratedField::CreatedNs),
                            "topic" => Ok(GeneratedField::Topic),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MessageHeaderV2;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.MessageHeaderV2")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<MessageHeaderV2, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut created_ns__ = None;
                let mut topic__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::CreatedNs => {
                            if created_ns__.is_some() {
                                return Err(serde::de::Error::duplicate_field("createdNs"));
                            }
                            created_ns__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Topic => {
                            if topic__.is_some() {
                                return Err(serde::de::Error::duplicate_field("topic"));
                            }
                            topic__ = Some(map.next_value()?);
                        }
                    }
                }
                Ok(MessageHeaderV2 {
                    created_ns: created_ns__.unwrap_or_default(),
                    topic: topic__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.MessageHeaderV2", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MessageV1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.header_bytes.is_empty() {
            len += 1;
        }
        if self.ciphertext.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.MessageV1", len)?;
        if !self.header_bytes.is_empty() {
            struct_ser.serialize_field("headerBytes", pbjson::private::base64::encode(&self.header_bytes).as_str())?;
        }
        if let Some(v) = self.ciphertext.as_ref() {
            struct_ser.serialize_field("ciphertext", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MessageV1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "header_bytes",
            "headerBytes",
            "ciphertext",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            HeaderBytes,
            Ciphertext,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "headerBytes" | "header_bytes" => Ok(GeneratedField::HeaderBytes),
                            "ciphertext" => Ok(GeneratedField::Ciphertext),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MessageV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.MessageV1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<MessageV1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut header_bytes__ = None;
                let mut ciphertext__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::HeaderBytes => {
                            if header_bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("headerBytes"));
                            }
                            header_bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Ciphertext => {
                            if ciphertext__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ciphertext"));
                            }
                            ciphertext__ = map.next_value()?;
                        }
                    }
                }
                Ok(MessageV1 {
                    header_bytes: header_bytes__.unwrap_or_default(),
                    ciphertext: ciphertext__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.MessageV1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MessageV2 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.header_bytes.is_empty() {
            len += 1;
        }
        if self.ciphertext.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.MessageV2", len)?;
        if !self.header_bytes.is_empty() {
            struct_ser.serialize_field("headerBytes", pbjson::private::base64::encode(&self.header_bytes).as_str())?;
        }
        if let Some(v) = self.ciphertext.as_ref() {
            struct_ser.serialize_field("ciphertext", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MessageV2 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "header_bytes",
            "headerBytes",
            "ciphertext",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            HeaderBytes,
            Ciphertext,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "headerBytes" | "header_bytes" => Ok(GeneratedField::HeaderBytes),
                            "ciphertext" => Ok(GeneratedField::Ciphertext),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MessageV2;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.MessageV2")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<MessageV2, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut header_bytes__ = None;
                let mut ciphertext__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::HeaderBytes => {
                            if header_bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("headerBytes"));
                            }
                            header_bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Ciphertext => {
                            if ciphertext__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ciphertext"));
                            }
                            ciphertext__ = map.next_value()?;
                        }
                    }
                }
                Ok(MessageV2 {
                    header_bytes: header_bytes__.unwrap_or_default(),
                    ciphertext: ciphertext__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.MessageV2", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for PrivateKey {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.timestamp != 0 {
            len += 1;
        }
        if self.public_key.is_some() {
            len += 1;
        }
        if self.union.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.PrivateKey", len)?;
        if self.timestamp != 0 {
            struct_ser.serialize_field("timestamp", ToString::to_string(&self.timestamp).as_str())?;
        }
        if let Some(v) = self.public_key.as_ref() {
            struct_ser.serialize_field("publicKey", v)?;
        }
        if let Some(v) = self.union.as_ref() {
            match v {
                private_key::Union::Secp256k1(v) => {
                    struct_ser.serialize_field("secp256k1", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for PrivateKey {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "timestamp",
            "public_key",
            "publicKey",
            "secp256k1",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Timestamp,
            PublicKey,
            Secp256k1,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "timestamp" => Ok(GeneratedField::Timestamp),
                            "publicKey" | "public_key" => Ok(GeneratedField::PublicKey),
                            "secp256k1" => Ok(GeneratedField::Secp256k1),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.PrivateKey")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<PrivateKey, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut timestamp__ = None;
                let mut public_key__ = None;
                let mut union__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Timestamp => {
                            if timestamp__.is_some() {
                                return Err(serde::de::Error::duplicate_field("timestamp"));
                            }
                            timestamp__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::PublicKey => {
                            if public_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("publicKey"));
                            }
                            public_key__ = map.next_value()?;
                        }
                        GeneratedField::Secp256k1 => {
                            if union__.is_some() {
                                return Err(serde::de::Error::duplicate_field("secp256k1"));
                            }
                            union__ = map.next_value::<::std::option::Option<_>>()?.map(private_key::Union::Secp256k1)
;
                        }
                    }
                }
                Ok(PrivateKey {
                    timestamp: timestamp__.unwrap_or_default(),
                    public_key: public_key__,
                    union: union__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.PrivateKey", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for private_key::Secp256k1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.bytes.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.PrivateKey.Secp256k1", len)?;
        if !self.bytes.is_empty() {
            struct_ser.serialize_field("bytes", pbjson::private::base64::encode(&self.bytes).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for private_key::Secp256k1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "bytes",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Bytes,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "bytes" => Ok(GeneratedField::Bytes),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = private_key::Secp256k1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.PrivateKey.Secp256k1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<private_key::Secp256k1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut bytes__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Bytes => {
                            if bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bytes"));
                            }
                            bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(private_key::Secp256k1 {
                    bytes: bytes__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.PrivateKey.Secp256k1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for PrivateKeyBundle {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.version.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.PrivateKeyBundle", len)?;
        if let Some(v) = self.version.as_ref() {
            match v {
                private_key_bundle::Version::V1(v) => {
                    struct_ser.serialize_field("v1", v)?;
                }
                private_key_bundle::Version::V2(v) => {
                    struct_ser.serialize_field("v2", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for PrivateKeyBundle {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "v1",
            "v2",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            V1,
            V2,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "v1" => Ok(GeneratedField::V1),
                            "v2" => Ok(GeneratedField::V2),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = PrivateKeyBundle;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.PrivateKeyBundle")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<PrivateKeyBundle, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut version__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::V1 => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("v1"));
                            }
                            version__ = map.next_value::<::std::option::Option<_>>()?.map(private_key_bundle::Version::V1)
;
                        }
                        GeneratedField::V2 => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("v2"));
                            }
                            version__ = map.next_value::<::std::option::Option<_>>()?.map(private_key_bundle::Version::V2)
;
                        }
                    }
                }
                Ok(PrivateKeyBundle {
                    version: version__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.PrivateKeyBundle", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for PrivateKeyBundleV1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.identity_key.is_some() {
            len += 1;
        }
        if !self.pre_keys.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.PrivateKeyBundleV1", len)?;
        if let Some(v) = self.identity_key.as_ref() {
            struct_ser.serialize_field("identityKey", v)?;
        }
        if !self.pre_keys.is_empty() {
            struct_ser.serialize_field("preKeys", &self.pre_keys)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for PrivateKeyBundleV1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "identity_key",
            "identityKey",
            "pre_keys",
            "preKeys",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            IdentityKey,
            PreKeys,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "identityKey" | "identity_key" => Ok(GeneratedField::IdentityKey),
                            "preKeys" | "pre_keys" => Ok(GeneratedField::PreKeys),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = PrivateKeyBundleV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.PrivateKeyBundleV1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<PrivateKeyBundleV1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut identity_key__ = None;
                let mut pre_keys__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::IdentityKey => {
                            if identity_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("identityKey"));
                            }
                            identity_key__ = map.next_value()?;
                        }
                        GeneratedField::PreKeys => {
                            if pre_keys__.is_some() {
                                return Err(serde::de::Error::duplicate_field("preKeys"));
                            }
                            pre_keys__ = Some(map.next_value()?);
                        }
                    }
                }
                Ok(PrivateKeyBundleV1 {
                    identity_key: identity_key__,
                    pre_keys: pre_keys__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.PrivateKeyBundleV1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for PrivateKeyBundleV2 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.identity_key.is_some() {
            len += 1;
        }
        if !self.pre_keys.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.PrivateKeyBundleV2", len)?;
        if let Some(v) = self.identity_key.as_ref() {
            struct_ser.serialize_field("identityKey", v)?;
        }
        if !self.pre_keys.is_empty() {
            struct_ser.serialize_field("preKeys", &self.pre_keys)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for PrivateKeyBundleV2 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "identity_key",
            "identityKey",
            "pre_keys",
            "preKeys",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            IdentityKey,
            PreKeys,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "identityKey" | "identity_key" => Ok(GeneratedField::IdentityKey),
                            "preKeys" | "pre_keys" => Ok(GeneratedField::PreKeys),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = PrivateKeyBundleV2;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.PrivateKeyBundleV2")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<PrivateKeyBundleV2, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut identity_key__ = None;
                let mut pre_keys__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::IdentityKey => {
                            if identity_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("identityKey"));
                            }
                            identity_key__ = map.next_value()?;
                        }
                        GeneratedField::PreKeys => {
                            if pre_keys__.is_some() {
                                return Err(serde::de::Error::duplicate_field("preKeys"));
                            }
                            pre_keys__ = Some(map.next_value()?);
                        }
                    }
                }
                Ok(PrivateKeyBundleV2 {
                    identity_key: identity_key__,
                    pre_keys: pre_keys__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.PrivateKeyBundleV2", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for PublicKey {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.timestamp != 0 {
            len += 1;
        }
        if self.signature.is_some() {
            len += 1;
        }
        if self.union.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.PublicKey", len)?;
        if self.timestamp != 0 {
            struct_ser.serialize_field("timestamp", ToString::to_string(&self.timestamp).as_str())?;
        }
        if let Some(v) = self.signature.as_ref() {
            struct_ser.serialize_field("signature", v)?;
        }
        if let Some(v) = self.union.as_ref() {
            match v {
                public_key::Union::Secp256k1Uncompressed(v) => {
                    struct_ser.serialize_field("secp256k1Uncompressed", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for PublicKey {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "timestamp",
            "signature",
            "secp256k1_uncompressed",
            "secp256k1Uncompressed",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Timestamp,
            Signature,
            Secp256k1Uncompressed,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "timestamp" => Ok(GeneratedField::Timestamp),
                            "signature" => Ok(GeneratedField::Signature),
                            "secp256k1Uncompressed" | "secp256k1_uncompressed" => Ok(GeneratedField::Secp256k1Uncompressed),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.PublicKey")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<PublicKey, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut timestamp__ = None;
                let mut signature__ = None;
                let mut union__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Timestamp => {
                            if timestamp__.is_some() {
                                return Err(serde::de::Error::duplicate_field("timestamp"));
                            }
                            timestamp__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Signature => {
                            if signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature__ = map.next_value()?;
                        }
                        GeneratedField::Secp256k1Uncompressed => {
                            if union__.is_some() {
                                return Err(serde::de::Error::duplicate_field("secp256k1Uncompressed"));
                            }
                            union__ = map.next_value::<::std::option::Option<_>>()?.map(public_key::Union::Secp256k1Uncompressed)
;
                        }
                    }
                }
                Ok(PublicKey {
                    timestamp: timestamp__.unwrap_or_default(),
                    signature: signature__,
                    union: union__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.PublicKey", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for public_key::Secp256k1Uncompressed {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.bytes.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.PublicKey.Secp256k1Uncompressed", len)?;
        if !self.bytes.is_empty() {
            struct_ser.serialize_field("bytes", pbjson::private::base64::encode(&self.bytes).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for public_key::Secp256k1Uncompressed {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "bytes",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Bytes,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "bytes" => Ok(GeneratedField::Bytes),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = public_key::Secp256k1Uncompressed;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.PublicKey.Secp256k1Uncompressed")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<public_key::Secp256k1Uncompressed, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut bytes__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Bytes => {
                            if bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bytes"));
                            }
                            bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(public_key::Secp256k1Uncompressed {
                    bytes: bytes__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.PublicKey.Secp256k1Uncompressed", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for PublicKeyBundle {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.identity_key.is_some() {
            len += 1;
        }
        if self.pre_key.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.PublicKeyBundle", len)?;
        if let Some(v) = self.identity_key.as_ref() {
            struct_ser.serialize_field("identityKey", v)?;
        }
        if let Some(v) = self.pre_key.as_ref() {
            struct_ser.serialize_field("preKey", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for PublicKeyBundle {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "identity_key",
            "identityKey",
            "pre_key",
            "preKey",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            IdentityKey,
            PreKey,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "identityKey" | "identity_key" => Ok(GeneratedField::IdentityKey),
                            "preKey" | "pre_key" => Ok(GeneratedField::PreKey),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = PublicKeyBundle;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.PublicKeyBundle")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<PublicKeyBundle, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut identity_key__ = None;
                let mut pre_key__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::IdentityKey => {
                            if identity_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("identityKey"));
                            }
                            identity_key__ = map.next_value()?;
                        }
                        GeneratedField::PreKey => {
                            if pre_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("preKey"));
                            }
                            pre_key__ = map.next_value()?;
                        }
                    }
                }
                Ok(PublicKeyBundle {
                    identity_key: identity_key__,
                    pre_key: pre_key__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.PublicKeyBundle", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SealedInvitation {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.version.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SealedInvitation", len)?;
        if let Some(v) = self.version.as_ref() {
            match v {
                sealed_invitation::Version::V1(v) => {
                    struct_ser.serialize_field("v1", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SealedInvitation {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "v1",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            V1,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "v1" => Ok(GeneratedField::V1),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SealedInvitation;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SealedInvitation")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SealedInvitation, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut version__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::V1 => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("v1"));
                            }
                            version__ = map.next_value::<::std::option::Option<_>>()?.map(sealed_invitation::Version::V1)
;
                        }
                    }
                }
                Ok(SealedInvitation {
                    version: version__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SealedInvitation", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SealedInvitationHeaderV1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.sender.is_some() {
            len += 1;
        }
        if self.recipient.is_some() {
            len += 1;
        }
        if self.created_ns != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SealedInvitationHeaderV1", len)?;
        if let Some(v) = self.sender.as_ref() {
            struct_ser.serialize_field("sender", v)?;
        }
        if let Some(v) = self.recipient.as_ref() {
            struct_ser.serialize_field("recipient", v)?;
        }
        if self.created_ns != 0 {
            struct_ser.serialize_field("createdNs", ToString::to_string(&self.created_ns).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SealedInvitationHeaderV1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "sender",
            "recipient",
            "created_ns",
            "createdNs",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Sender,
            Recipient,
            CreatedNs,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "sender" => Ok(GeneratedField::Sender),
                            "recipient" => Ok(GeneratedField::Recipient),
                            "createdNs" | "created_ns" => Ok(GeneratedField::CreatedNs),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SealedInvitationHeaderV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SealedInvitationHeaderV1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SealedInvitationHeaderV1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut sender__ = None;
                let mut recipient__ = None;
                let mut created_ns__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Sender => {
                            if sender__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sender"));
                            }
                            sender__ = map.next_value()?;
                        }
                        GeneratedField::Recipient => {
                            if recipient__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recipient"));
                            }
                            recipient__ = map.next_value()?;
                        }
                        GeneratedField::CreatedNs => {
                            if created_ns__.is_some() {
                                return Err(serde::de::Error::duplicate_field("createdNs"));
                            }
                            created_ns__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(SealedInvitationHeaderV1 {
                    sender: sender__,
                    recipient: recipient__,
                    created_ns: created_ns__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SealedInvitationHeaderV1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SealedInvitationV1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.header_bytes.is_empty() {
            len += 1;
        }
        if self.ciphertext.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SealedInvitationV1", len)?;
        if !self.header_bytes.is_empty() {
            struct_ser.serialize_field("headerBytes", pbjson::private::base64::encode(&self.header_bytes).as_str())?;
        }
        if let Some(v) = self.ciphertext.as_ref() {
            struct_ser.serialize_field("ciphertext", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SealedInvitationV1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "header_bytes",
            "headerBytes",
            "ciphertext",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            HeaderBytes,
            Ciphertext,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "headerBytes" | "header_bytes" => Ok(GeneratedField::HeaderBytes),
                            "ciphertext" => Ok(GeneratedField::Ciphertext),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SealedInvitationV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SealedInvitationV1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SealedInvitationV1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut header_bytes__ = None;
                let mut ciphertext__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::HeaderBytes => {
                            if header_bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("headerBytes"));
                            }
                            header_bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Ciphertext => {
                            if ciphertext__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ciphertext"));
                            }
                            ciphertext__ = map.next_value()?;
                        }
                    }
                }
                Ok(SealedInvitationV1 {
                    header_bytes: header_bytes__.unwrap_or_default(),
                    ciphertext: ciphertext__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SealedInvitationV1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Signature {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.union.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.Signature", len)?;
        if let Some(v) = self.union.as_ref() {
            match v {
                signature::Union::EcdsaCompact(v) => {
                    struct_ser.serialize_field("ecdsaCompact", v)?;
                }
                signature::Union::WalletEcdsaCompact(v) => {
                    struct_ser.serialize_field("walletEcdsaCompact", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Signature {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "ecdsa_compact",
            "ecdsaCompact",
            "wallet_ecdsa_compact",
            "walletEcdsaCompact",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            EcdsaCompact,
            WalletEcdsaCompact,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "ecdsaCompact" | "ecdsa_compact" => Ok(GeneratedField::EcdsaCompact),
                            "walletEcdsaCompact" | "wallet_ecdsa_compact" => Ok(GeneratedField::WalletEcdsaCompact),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.Signature")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<Signature, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut union__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::EcdsaCompact => {
                            if union__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ecdsaCompact"));
                            }
                            union__ = map.next_value::<::std::option::Option<_>>()?.map(signature::Union::EcdsaCompact)
;
                        }
                        GeneratedField::WalletEcdsaCompact => {
                            if union__.is_some() {
                                return Err(serde::de::Error::duplicate_field("walletEcdsaCompact"));
                            }
                            union__ = map.next_value::<::std::option::Option<_>>()?.map(signature::Union::WalletEcdsaCompact)
;
                        }
                    }
                }
                Ok(Signature {
                    union: union__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.Signature", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for signature::EcdsaCompact {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.bytes.is_empty() {
            len += 1;
        }
        if self.recovery != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.Signature.ECDSACompact", len)?;
        if !self.bytes.is_empty() {
            struct_ser.serialize_field("bytes", pbjson::private::base64::encode(&self.bytes).as_str())?;
        }
        if self.recovery != 0 {
            struct_ser.serialize_field("recovery", &self.recovery)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for signature::EcdsaCompact {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "bytes",
            "recovery",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Bytes,
            Recovery,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "bytes" => Ok(GeneratedField::Bytes),
                            "recovery" => Ok(GeneratedField::Recovery),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = signature::EcdsaCompact;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.Signature.ECDSACompact")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<signature::EcdsaCompact, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut bytes__ = None;
                let mut recovery__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Bytes => {
                            if bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bytes"));
                            }
                            bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Recovery => {
                            if recovery__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recovery"));
                            }
                            recovery__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(signature::EcdsaCompact {
                    bytes: bytes__.unwrap_or_default(),
                    recovery: recovery__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.Signature.ECDSACompact", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for signature::WalletEcdsaCompact {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.bytes.is_empty() {
            len += 1;
        }
        if self.recovery != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.Signature.WalletECDSACompact", len)?;
        if !self.bytes.is_empty() {
            struct_ser.serialize_field("bytes", pbjson::private::base64::encode(&self.bytes).as_str())?;
        }
        if self.recovery != 0 {
            struct_ser.serialize_field("recovery", &self.recovery)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for signature::WalletEcdsaCompact {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "bytes",
            "recovery",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Bytes,
            Recovery,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "bytes" => Ok(GeneratedField::Bytes),
                            "recovery" => Ok(GeneratedField::Recovery),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = signature::WalletEcdsaCompact;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.Signature.WalletECDSACompact")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<signature::WalletEcdsaCompact, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut bytes__ = None;
                let mut recovery__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Bytes => {
                            if bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bytes"));
                            }
                            bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Recovery => {
                            if recovery__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recovery"));
                            }
                            recovery__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(signature::WalletEcdsaCompact {
                    bytes: bytes__.unwrap_or_default(),
                    recovery: recovery__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.Signature.WalletECDSACompact", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SignedContent {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.payload.is_empty() {
            len += 1;
        }
        if self.sender.is_some() {
            len += 1;
        }
        if self.signature.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SignedContent", len)?;
        if !self.payload.is_empty() {
            struct_ser.serialize_field("payload", pbjson::private::base64::encode(&self.payload).as_str())?;
        }
        if let Some(v) = self.sender.as_ref() {
            struct_ser.serialize_field("sender", v)?;
        }
        if let Some(v) = self.signature.as_ref() {
            struct_ser.serialize_field("signature", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SignedContent {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "payload",
            "sender",
            "signature",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Payload,
            Sender,
            Signature,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "payload" => Ok(GeneratedField::Payload),
                            "sender" => Ok(GeneratedField::Sender),
                            "signature" => Ok(GeneratedField::Signature),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SignedContent;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SignedContent")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SignedContent, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut payload__ = None;
                let mut sender__ = None;
                let mut signature__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Payload => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("payload"));
                            }
                            payload__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Sender => {
                            if sender__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sender"));
                            }
                            sender__ = map.next_value()?;
                        }
                        GeneratedField::Signature => {
                            if signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature__ = map.next_value()?;
                        }
                    }
                }
                Ok(SignedContent {
                    payload: payload__.unwrap_or_default(),
                    sender: sender__,
                    signature: signature__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SignedContent", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SignedEciesCiphertext {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.ecies_bytes.is_empty() {
            len += 1;
        }
        if self.signature.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SignedEciesCiphertext", len)?;
        if !self.ecies_bytes.is_empty() {
            struct_ser.serialize_field("eciesBytes", pbjson::private::base64::encode(&self.ecies_bytes).as_str())?;
        }
        if let Some(v) = self.signature.as_ref() {
            struct_ser.serialize_field("signature", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SignedEciesCiphertext {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "ecies_bytes",
            "eciesBytes",
            "signature",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            EciesBytes,
            Signature,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "eciesBytes" | "ecies_bytes" => Ok(GeneratedField::EciesBytes),
                            "signature" => Ok(GeneratedField::Signature),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SignedEciesCiphertext;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SignedEciesCiphertext")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SignedEciesCiphertext, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut ecies_bytes__ = None;
                let mut signature__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::EciesBytes => {
                            if ecies_bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("eciesBytes"));
                            }
                            ecies_bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Signature => {
                            if signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature__ = map.next_value()?;
                        }
                    }
                }
                Ok(SignedEciesCiphertext {
                    ecies_bytes: ecies_bytes__.unwrap_or_default(),
                    signature: signature__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SignedEciesCiphertext", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for signed_ecies_ciphertext::Ecies {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.ephemeral_public_key.is_empty() {
            len += 1;
        }
        if !self.iv.is_empty() {
            len += 1;
        }
        if !self.mac.is_empty() {
            len += 1;
        }
        if !self.ciphertext.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SignedEciesCiphertext.Ecies", len)?;
        if !self.ephemeral_public_key.is_empty() {
            struct_ser.serialize_field("ephemeralPublicKey", pbjson::private::base64::encode(&self.ephemeral_public_key).as_str())?;
        }
        if !self.iv.is_empty() {
            struct_ser.serialize_field("iv", pbjson::private::base64::encode(&self.iv).as_str())?;
        }
        if !self.mac.is_empty() {
            struct_ser.serialize_field("mac", pbjson::private::base64::encode(&self.mac).as_str())?;
        }
        if !self.ciphertext.is_empty() {
            struct_ser.serialize_field("ciphertext", pbjson::private::base64::encode(&self.ciphertext).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for signed_ecies_ciphertext::Ecies {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "ephemeral_public_key",
            "ephemeralPublicKey",
            "iv",
            "mac",
            "ciphertext",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            EphemeralPublicKey,
            Iv,
            Mac,
            Ciphertext,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "ephemeralPublicKey" | "ephemeral_public_key" => Ok(GeneratedField::EphemeralPublicKey),
                            "iv" => Ok(GeneratedField::Iv),
                            "mac" => Ok(GeneratedField::Mac),
                            "ciphertext" => Ok(GeneratedField::Ciphertext),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = signed_ecies_ciphertext::Ecies;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SignedEciesCiphertext.Ecies")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<signed_ecies_ciphertext::Ecies, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut ephemeral_public_key__ = None;
                let mut iv__ = None;
                let mut mac__ = None;
                let mut ciphertext__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::EphemeralPublicKey => {
                            if ephemeral_public_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ephemeralPublicKey"));
                            }
                            ephemeral_public_key__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Iv => {
                            if iv__.is_some() {
                                return Err(serde::de::Error::duplicate_field("iv"));
                            }
                            iv__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Mac => {
                            if mac__.is_some() {
                                return Err(serde::de::Error::duplicate_field("mac"));
                            }
                            mac__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Ciphertext => {
                            if ciphertext__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ciphertext"));
                            }
                            ciphertext__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(signed_ecies_ciphertext::Ecies {
                    ephemeral_public_key: ephemeral_public_key__.unwrap_or_default(),
                    iv: iv__.unwrap_or_default(),
                    mac: mac__.unwrap_or_default(),
                    ciphertext: ciphertext__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SignedEciesCiphertext.Ecies", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SignedPrivateKey {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.created_ns != 0 {
            len += 1;
        }
        if self.public_key.is_some() {
            len += 1;
        }
        if self.union.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SignedPrivateKey", len)?;
        if self.created_ns != 0 {
            struct_ser.serialize_field("createdNs", ToString::to_string(&self.created_ns).as_str())?;
        }
        if let Some(v) = self.public_key.as_ref() {
            struct_ser.serialize_field("publicKey", v)?;
        }
        if let Some(v) = self.union.as_ref() {
            match v {
                signed_private_key::Union::Secp256k1(v) => {
                    struct_ser.serialize_field("secp256k1", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SignedPrivateKey {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "created_ns",
            "createdNs",
            "public_key",
            "publicKey",
            "secp256k1",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            CreatedNs,
            PublicKey,
            Secp256k1,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "createdNs" | "created_ns" => Ok(GeneratedField::CreatedNs),
                            "publicKey" | "public_key" => Ok(GeneratedField::PublicKey),
                            "secp256k1" => Ok(GeneratedField::Secp256k1),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SignedPrivateKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SignedPrivateKey")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SignedPrivateKey, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut created_ns__ = None;
                let mut public_key__ = None;
                let mut union__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::CreatedNs => {
                            if created_ns__.is_some() {
                                return Err(serde::de::Error::duplicate_field("createdNs"));
                            }
                            created_ns__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::PublicKey => {
                            if public_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("publicKey"));
                            }
                            public_key__ = map.next_value()?;
                        }
                        GeneratedField::Secp256k1 => {
                            if union__.is_some() {
                                return Err(serde::de::Error::duplicate_field("secp256k1"));
                            }
                            union__ = map.next_value::<::std::option::Option<_>>()?.map(signed_private_key::Union::Secp256k1)
;
                        }
                    }
                }
                Ok(SignedPrivateKey {
                    created_ns: created_ns__.unwrap_or_default(),
                    public_key: public_key__,
                    union: union__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SignedPrivateKey", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for signed_private_key::Secp256k1 {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.bytes.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SignedPrivateKey.Secp256k1", len)?;
        if !self.bytes.is_empty() {
            struct_ser.serialize_field("bytes", pbjson::private::base64::encode(&self.bytes).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for signed_private_key::Secp256k1 {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "bytes",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Bytes,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "bytes" => Ok(GeneratedField::Bytes),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = signed_private_key::Secp256k1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SignedPrivateKey.Secp256k1")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<signed_private_key::Secp256k1, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut bytes__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Bytes => {
                            if bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bytes"));
                            }
                            bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(signed_private_key::Secp256k1 {
                    bytes: bytes__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SignedPrivateKey.Secp256k1", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SignedPublicKey {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.key_bytes.is_empty() {
            len += 1;
        }
        if self.signature.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SignedPublicKey", len)?;
        if !self.key_bytes.is_empty() {
            struct_ser.serialize_field("keyBytes", pbjson::private::base64::encode(&self.key_bytes).as_str())?;
        }
        if let Some(v) = self.signature.as_ref() {
            struct_ser.serialize_field("signature", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SignedPublicKey {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "key_bytes",
            "keyBytes",
            "signature",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            KeyBytes,
            Signature,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "keyBytes" | "key_bytes" => Ok(GeneratedField::KeyBytes),
                            "signature" => Ok(GeneratedField::Signature),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SignedPublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SignedPublicKey")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SignedPublicKey, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut key_bytes__ = None;
                let mut signature__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::KeyBytes => {
                            if key_bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keyBytes"));
                            }
                            key_bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Signature => {
                            if signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature__ = map.next_value()?;
                        }
                    }
                }
                Ok(SignedPublicKey {
                    key_bytes: key_bytes__.unwrap_or_default(),
                    signature: signature__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SignedPublicKey", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SignedPublicKeyBundle {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.identity_key.is_some() {
            len += 1;
        }
        if self.pre_key.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.SignedPublicKeyBundle", len)?;
        if let Some(v) = self.identity_key.as_ref() {
            struct_ser.serialize_field("identityKey", v)?;
        }
        if let Some(v) = self.pre_key.as_ref() {
            struct_ser.serialize_field("preKey", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SignedPublicKeyBundle {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "identity_key",
            "identityKey",
            "pre_key",
            "preKey",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            IdentityKey,
            PreKey,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "identityKey" | "identity_key" => Ok(GeneratedField::IdentityKey),
                            "preKey" | "pre_key" => Ok(GeneratedField::PreKey),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SignedPublicKeyBundle;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.SignedPublicKeyBundle")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SignedPublicKeyBundle, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut identity_key__ = None;
                let mut pre_key__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::IdentityKey => {
                            if identity_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("identityKey"));
                            }
                            identity_key__ = map.next_value()?;
                        }
                        GeneratedField::PreKey => {
                            if pre_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("preKey"));
                            }
                            pre_key__ = map.next_value()?;
                        }
                    }
                }
                Ok(SignedPublicKeyBundle {
                    identity_key: identity_key__,
                    pre_key: pre_key__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.SignedPublicKeyBundle", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for UnsignedPublicKey {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.created_ns != 0 {
            len += 1;
        }
        if self.union.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.UnsignedPublicKey", len)?;
        if self.created_ns != 0 {
            struct_ser.serialize_field("createdNs", ToString::to_string(&self.created_ns).as_str())?;
        }
        if let Some(v) = self.union.as_ref() {
            match v {
                unsigned_public_key::Union::Secp256k1Uncompressed(v) => {
                    struct_ser.serialize_field("secp256k1Uncompressed", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for UnsignedPublicKey {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "created_ns",
            "createdNs",
            "secp256k1_uncompressed",
            "secp256k1Uncompressed",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            CreatedNs,
            Secp256k1Uncompressed,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "createdNs" | "created_ns" => Ok(GeneratedField::CreatedNs),
                            "secp256k1Uncompressed" | "secp256k1_uncompressed" => Ok(GeneratedField::Secp256k1Uncompressed),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = UnsignedPublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.UnsignedPublicKey")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<UnsignedPublicKey, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut created_ns__ = None;
                let mut union__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::CreatedNs => {
                            if created_ns__.is_some() {
                                return Err(serde::de::Error::duplicate_field("createdNs"));
                            }
                            created_ns__ = 
                                Some(map.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Secp256k1Uncompressed => {
                            if union__.is_some() {
                                return Err(serde::de::Error::duplicate_field("secp256k1Uncompressed"));
                            }
                            union__ = map.next_value::<::std::option::Option<_>>()?.map(unsigned_public_key::Union::Secp256k1Uncompressed)
;
                        }
                    }
                }
                Ok(UnsignedPublicKey {
                    created_ns: created_ns__.unwrap_or_default(),
                    union: union__,
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.UnsignedPublicKey", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for unsigned_public_key::Secp256k1Uncompressed {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.bytes.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("xmtp.message_contents.UnsignedPublicKey.Secp256k1Uncompressed", len)?;
        if !self.bytes.is_empty() {
            struct_ser.serialize_field("bytes", pbjson::private::base64::encode(&self.bytes).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for unsigned_public_key::Secp256k1Uncompressed {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "bytes",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Bytes,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "bytes" => Ok(GeneratedField::Bytes),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = unsigned_public_key::Secp256k1Uncompressed;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct xmtp.message_contents.UnsignedPublicKey.Secp256k1Uncompressed")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<unsigned_public_key::Secp256k1Uncompressed, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut bytes__ = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        GeneratedField::Bytes => {
                            if bytes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bytes"));
                            }
                            bytes__ = 
                                Some(map.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(unsigned_public_key::Secp256k1Uncompressed {
                    bytes: bytes__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("xmtp.message_contents.UnsignedPublicKey.Secp256k1Uncompressed", FIELDS, GeneratedVisitor)
    }
}