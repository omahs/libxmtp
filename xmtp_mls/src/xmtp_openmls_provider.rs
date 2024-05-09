use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::storage::{db_connection::DbConnection, sql_key_store::SqlKeyStore};

#[derive(Debug)]
pub struct XmtpOpenMlsProvider {
    crypto: RustCrypto,
    key_store: SqlKeyStore,
}

impl Clone for XmtpOpenMlsProvider {
    fn clone(&self) -> Self {
        Self {
            crypto: RustCrypto::default(),
            key_store: self.key_store.clone(),
        }
    }
}

impl XmtpOpenMlsProvider {
    pub fn new(conn: DbConnection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            key_store: SqlKeyStore::new(conn),
        }
    }

    pub(crate) fn conn(&self) -> &DbConnection {
        self.key_store.conn()
    }
}

impl OpenMlsProvider for XmtpOpenMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = SqlKeyStore;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }
}
