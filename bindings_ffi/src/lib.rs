pub mod inbox_owner;
pub mod logger;

use inbox_owner::FfiInboxOwner;
use log::info;
use logger::FfiLogger;
use std::error::Error;
use std::sync::Arc;
use xmtp::types::Address;
use xmtp_networking::grpc_api_helper::Client as TonicApiClient;

use crate::inbox_owner::RustInboxOwner;
pub use crate::inbox_owner::SigningError;
use crate::logger::init_logger;

pub type RustXmtpClient = xmtp::Client<TonicApiClient>;
uniffi::include_scaffolding!("xmtpv3");

#[derive(uniffi::Error, Debug)]
#[uniffi(handle_unknown_callback_error)]
pub enum GenericError {
    Generic { err: String },
}

impl From<String> for GenericError {
    fn from(err: String) -> Self {
        Self::Generic { err }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for GenericError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Generic { err: e.reason }
    }
}

// TODO Use non-string errors across Uniffi interface
fn stringify_error_chain(error: &(dyn Error + 'static)) -> String {
    let mut result = format!("Error: {}\n", error);

    let mut source = error.source();
    while let Some(src) = source {
        result += &format!("Caused by: {}\n", src);
        source = src.source();
    }

    result
}

#[uniffi::export]
pub fn enable_logging(logger: Box<dyn FfiLogger>) {
    init_logger(logger)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn create_client(
    ffi_inbox_owner: Box<dyn FfiInboxOwner>,
    host: String,
    is_secure: bool,
    // TODO proper error handling
) -> Result<Arc<FfiXmtpClient>, GenericError> {
    let inbox_owner = RustInboxOwner::new(ffi_inbox_owner);
    let api_client = TonicApiClient::create(host.clone(), is_secure)
        .await
        .map_err(|e| stringify_error_chain(&e))?;

    let mut xmtp_client: RustXmtpClient = xmtp::ClientBuilder::new(inbox_owner.into())
        .api_client(api_client)
        .build()
        .map_err(|e| stringify_error_chain(&e))?;
    xmtp_client
        .init()
        .await
        .map_err(|e| stringify_error_chain(&e))?;

    info!(
        "Created XMTP client for address: {}",
        xmtp_client.wallet_address()
    );
    Ok(Arc::new(FfiXmtpClient {
        inner_client: xmtp_client,
    }))
}

#[derive(uniffi::Object)]
pub struct FfiXmtpClient {
    inner_client: RustXmtpClient,
}

#[uniffi::export]
impl FfiXmtpClient {
    pub fn wallet_address(&self) -> Address {
        self.inner_client.wallet_address()
    }
}

#[cfg(test)]
mod tests {
    use crate::{create_client, inbox_owner::SigningError, logger::FfiLogger, FfiInboxOwner};
    use xmtp::InboxOwner;
    use xmtp_cryptography::{signature::RecoverableSignature, utils::rng};

    pub struct LocalWalletInboxOwner {
        wallet: xmtp_cryptography::utils::LocalWallet,
    }

    impl LocalWalletInboxOwner {
        pub fn new() -> Self {
            Self {
                wallet: xmtp_cryptography::utils::LocalWallet::new(&mut rng()),
            }
        }
    }

    impl FfiInboxOwner for LocalWalletInboxOwner {
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

    pub struct MockLogger {}

    impl FfiLogger for MockLogger {
        fn log(&self, _level: u32, _level_label: String, _message: String) {}
    }

    // Try a query on a test topic, and make sure we get a response
    #[tokio::test]
    async fn test_client_creation() {
        let ffi_inbox_owner = LocalWalletInboxOwner::new();
        let client = create_client(
            Box::new(ffi_inbox_owner),
            xmtp_networking::LOCALHOST_ADDRESS.to_string(),
            false,
        )
        .await
        .unwrap();
        assert!(!client.wallet_address().is_empty());
    }
}
