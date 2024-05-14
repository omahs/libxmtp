use wasm_bindgen::prelude::{wasm_bindgen, JsError};
pub use crate::inbox_owner::SigningError;
use crate::logger::init_logger;
use crate::logger::WasmLogger;
use crate::GenericError;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tokio::sync::oneshot::Sender;
use xmtp_api_grpc::grpc_api_helper::Client as TonicApiClient;
use xmtp_mls::groups::group_metadata::ConversationType;
use xmtp_mls::groups::group_metadata::GroupMetadata;
use xmtp_mls::groups::PreconfiguredPolicies;
use xmtp_mls::identity::v3::{IdentityStrategy, LegacyIdentity};
use xmtp_mls::{
    builder::ClientBuilder,
    client::Client as MlsClient,
    groups::MlsGroup,
    storage::{
        group_message::DeliveryStatus, group_message::GroupMessageKind,
        group_message::StoredGroupMessage, EncryptedMessageStore, EncryptionKey, StorageOption,
    },
    types::Address,
};
#[wasm_bindgen]
pub enum SigningError {
    Generic,
}

#[wasm_bindgen]
pub struct WasmInboxOwner {
    address: String,
}

#[wasm_bindgen]
impl WasmInboxOwner {
    #[wasm_bindgen(constructor)]
    pub fn new(address: String) -> WasmInboxOwner {
        WasmInboxOwner { address }
    }

    pub fn get_address(&self) -> String {
        self.address.clone()
    }

    pub fn sign(&self, text: String) -> Result<Vec<u8>, SigningError> {
        // Implement signing logic here.
        // Example: Returning error
        Err(SigningError::Generic)
    }
}

#[wasm_bindgen]
pub struct WasmLogger;

#[wasm_bindgen]
impl WasmLogger {
    pub fn log(level: u32, level_label: &str, message: &str) {
        // JavaScript console logging could be used directly or mapped here.
        log(&format!("{}: {} - {}", level, level_label, message));
    }
}

pub type RustXmtpClient = MlsClient<TonicApiClient>;

#[wasm_bindgen]
pub struct WasmXmtpClient {
    inner_client: Arc<RustXmtpClient>,
}

/// XMTP SDK's may embed libxmtp (v3) alongside existing v2 protocol logic
/// for backwards-compatibility purposes. In this case, the client may already
/// have a wallet-signed v2 key. Depending on the source of this key,
/// libxmtp may choose to bootstrap v3 installation keys using the existing
/// legacy key.
#[wasm_bindgen]
pub enum LegacyIdentitySource {
    // A client with no support for v2 messages
    None,
    // A cached v2 key was provided on client initialization
    Static,
    // A private bundle exists on the network from which the v2 key was fetched
    Network,
    // A new v2 key was generated on client initialization
    KeyGenerator,
}

#[wasm_bindgen]
impl WasmXmtpClient {
    pub fn account_address(&self) -> Address {
        self.inner_client.account_address()
    }

    // pub fn conversations(&self) -> Arc<FfiConversations> {
    //     Arc::new(FfiConversations {
    //         inner_client: self.inner_client.clone(),
    //     })
    // }

    pub async fn can_message(
        &self,
        account_addresses: Vec<String>,
    ) -> Result<HashMap<String, bool>, GenericError> {
        let inner = self.inner_client.as_ref();

        let results: HashMap<String, bool> = inner.can_message(account_addresses).await?;

        Ok(results)
    }

    pub fn installation_id(&self) -> Vec<u8> {
        self.inner_client.installation_public_key()
    }
}

#[wasm_bindgen]
impl WasmXmtpClient {
    #[allow(clippy::too_many_arguments)]
    #[allow(unused)]
    #[wasm_bindgen(constructor)]
    pub async fn create_client(
        logger: Box<dyn WasmLogger>,
        host: String,
        is_secure: bool,
        db: Option<String>,
        encryption_key: Option<Vec<u8>>,
        account_address: String,
        legacy_identity_source: LegacyIdentitySource,
        legacy_signed_private_key_proto: Option<Vec<u8>>,
    ) -> Result<Arc<WasmXmtpClient>, GenericError> {
        init_logger(logger);

        log::info!(
            "Creating API client for host: {}, isSecure: {}",
            host,
            is_secure
        );
        let api_client = TonicApiClient::create(host.clone(), is_secure).await?;

        log::info!(
            "Creating message store with path: {:?} and encryption key: {}",
            db,
            encryption_key.is_some()
        );

        let storage_option = match db {
            Some(path) => StorageOption::Persistent(path),
            None => StorageOption::Ephemeral,
        };

        let store = match encryption_key {
            Some(key) => {
                let key: EncryptionKey = key
                    .try_into()
                    .map_err(|_| "Malformed 32 byte encryption key".to_string())?;
                EncryptedMessageStore::new(storage_option, key)?
            }
            None => EncryptedMessageStore::new_unencrypted(storage_option)?,
        };

        log::info!("Creating XMTP client");
        let legacy_key_result =
            legacy_signed_private_key_proto.ok_or("No legacy key provided".to_string());
        let legacy_identity = match legacy_identity_source {
            LegacyIdentitySource::None => LegacyIdentity::None,
            LegacyIdentitySource::Static => LegacyIdentity::Static(legacy_key_result?),
            LegacyIdentitySource::Network => LegacyIdentity::Network(legacy_key_result?),
            LegacyIdentitySource::KeyGenerator => LegacyIdentity::KeyGenerator(legacy_key_result?),
        };
        let identity_strategy = IdentityStrategy::CreateIfNotFound(account_address, legacy_identity);
        let xmtp_client: RustXmtpClient = ClientBuilder::new(identity_strategy)
            .api_client(api_client)
            .store(store)
            .build()
            .await?;

        log::info!(
            "Created XMTP client for address: {}",
            xmtp_client.account_address()
        );
        Ok(Arc::new(WasmXmtpClient {
            inner_client: Arc::new(xmtp_client),
        }))
    }

    pub fn text_to_sign(&self) -> Option<String> {
        self.inner_client.text_to_sign()
    }

    pub fn register_identity(&self, recoverable_wallet_signature: Option<Uint8Array>) -> Promise {
        let signature_vec = recoverable_wallet_signature.map(|u8_array| u8_array.to_vec());
        future_to_promise(async move {
            match self.inner_client.register_identity(signature_vec).await {
                Ok(_) => Ok(JsValue::UNDEFINED),
                Err(e) => Err(JsValue::from_str(&e.to_string())), // Assuming GenericError implements Display
            }
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::{
        inbox_owner::SigningError, logger::WasmLogger,
        LegacyIdentitySource,
    };
    use std::{
        env,
        sync::{Arc, Mutex},
    };

    use super::{create_client, WasmXmtpClient};
    use ethers_core::rand::{
        self,
        distributions::{Alphanumeric, DistString},
    };
    use xmtp_cryptography::{signature::RecoverableSignature, utils::rng};
    use xmtp_mls::{storage::EncryptionKey};

    #[derive(Clone)]
    pub struct LocalWalletInboxOwner {
        wallet: xmtp_cryptography::utils::LocalWallet,
    }

    pub struct MockLogger {}

    impl WasmLogger for MockLogger {
        fn log(&self, _level: u32, level_label: String, message: String) {
            println!("{}: {}", level_label, message)
        }
    }

    pub fn rand_string() -> String {
        Alphanumeric.sample_string(&mut rand::thread_rng(), 24)
    }

    pub fn tmp_path() -> String {
        let db_name = rand_string();
        format!("{}/{}.db3", env::temp_dir().to_str().unwrap(), db_name)
    }

    fn static_enc_key() -> EncryptionKey {
        [2u8; 32]
    }

    impl LocalWalletInboxOwner {
        pub fn new() -> Self {
            Self {
                wallet: xmtp_cryptography::utils::LocalWallet::new(&mut rng()),
            }
        }
    }

    impl WasmInboxOwner for LocalWalletInboxOwner {
        fn get_address(&self) -> String {
            self.wallet.get_address()
        }

        fn sign(&self, text: String) -> Result<Vec<u8>, SigningError> {
            let recoverable_signature =
                self.wallet.sign(&text).map_err(|_| SigningError::Generic)?;
            match recoverable_signature {
                RecoverableSignature::Eip191Signature(signature_bytes) => Ok(signature_bytes),
            }
        }
    }

    async fn new_test_client() -> Arc<WasmXmtpClient> {
        let wasm_inbox_owner = LocalWalletInboxOwner::new();

        let client = create_client(
            Box::new(MockLogger {}),
            xmtp_api_grpc::LOCALHOST_ADDRESS.to_string(),
            false,
            Some(tmp_path()),
            None,
            wasm_inbox_owner.get_address(),
            LegacyIdentitySource::None,
            None,
        )
        .await
        .unwrap();

        let text_to_sign = client.text_to_sign().unwrap();
        let signature = wasm_inbox_owner.sign(text_to_sign).unwrap();

        client.register_identity(Some(signature)).await.unwrap();
        return client;
    }

    // Try a query on a test topic, and make sure we get a response
    #[tokio::test]
    async fn test_client_creation() {
        let client = new_test_client().await;
        assert!(!client.account_address().is_empty());
    }
}
