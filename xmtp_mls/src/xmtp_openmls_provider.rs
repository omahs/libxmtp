use diesel::{
    connection::{AnsiTransactionManager, TransactionManager as _},
    result::{DatabaseErrorKind, Error},
    SqliteConnection,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::storage::{db_connection::DbConnectionSync, sql_key_store::SqlKeyStore, StorageError};

#[derive(Debug, Clone)]
pub struct XmtpOpenMlsProvider {
    crypto: RustCrypto,
    key_store: SqlKeyStore,
}

impl XmtpOpenMlsProvider {
    pub fn new(conn: SqliteConnection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            key_store: SqlKeyStore::new(DbConnectionSync::new(conn)),
        }
    }

    pub async fn transaction_async<T, E, F, Fut>(&self, fun: F) -> Result<T, E>
    where
        F: Send + FnOnce(&Self) -> Fut,
        Fut: futures::Future<Output = Result<T, E>> + Send,
        E: From<diesel::result::Error>
            + From<StorageError>
            + From<deadpool_diesel::InteractError>
            + Send
            + 'static,
        T: Send,
    {
        let lock = self.key_store.conn().wrapped_conn;
        let mut conn = lock.lock();

        AnsiTransactionManager::begin_transaction(&mut *conn)?;
        let result = fun(self).await;

        match result {
            Ok(value) => {
                AnsiTransactionManager::commit_transaction(&mut *conn)?;
                log::debug!("Transaction async being committed");
                Ok(value)
            }
            Err(err) => {
                log::debug!("Transaction async being rolled back");
                match AnsiTransactionManager::rollback_transaction(&mut *conn) {
                    Ok(()) => Err(err),
                    Err(Error::BrokenTransactionManager) => Err(err),
                    Err(rollback) => Err(rollback.into()),
                }
            }
        }
    }

    pub(crate) fn conn(&self) -> DbConnectionSync {
        self.key_store.conn()
    }

    pub(crate) fn conn_ref(&self) -> &DbConnectionSync {
        self.key_store.conn_ref()
    }
}

impl<'conn> OpenMlsProvider for XmtpOpenMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqlKeyStore;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }
}

impl<'a> OpenMlsProvider for &'a XmtpOpenMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqlKeyStore;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }
}
