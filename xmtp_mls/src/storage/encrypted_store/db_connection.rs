use std::{fmt, sync::Arc};

use super::StorageError;
use deadpool_diesel::sqlite::Connection;
use diesel::SqliteConnection;

/// A wrapper for RawDbConnection that houses all XMTP DB operations.
#[derive(Clone)]
pub struct DbConnection {
    conn: Arc<Connection>,
}

/// Owned DBConnection Methods
/// Lifetime is 'static' because we are using [`RefOrValue::Value`] variant.
impl DbConnection {
    pub(crate) fn new(conn: Connection) -> Self {
        Self {
            conn: Arc::new(conn),
        }
    }

    pub(crate) async fn raw_query<F, R>(&self, fun: F) -> Result<R, StorageError>
    where
        F: FnOnce(&mut SqliteConnection) -> Result<R, diesel::result::Error> + Send + 'static,
        R: Send + 'static,
    {
        self.conn
            .interact(|conn| fun(conn).map_err(Into::into))
            .await?
    }

    /// Get a reference to the inner [`Connection`]
    pub(crate) fn inner(&self) -> Arc<Connection> {
        self.conn.clone()
    }
}

impl fmt::Debug for DbConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbConnection")
            .field("wrapped_conn", &"DbConnection")
            .finish()
    }
}

/// A wrapper for RawDbConnection that houses all XMTP DB operations.
/// Uses a [`Mutex]` internally for interior mutability, so that the connection
/// and transaction state can be shared between the OpenMLS Provider and
/// native XMTP operations
#[derive(Clone)]
pub struct DbConnectionSync {
    pub(crate) wrapped_conn: Arc<parking_lot::Mutex<SqliteConnection>>,
}

/// Owned DBConnection Methods
/// Lifetime is 'static' because we are using [`RefOrValue::Value`] variant.
impl DbConnectionSync {
    pub(crate) fn new(conn: SqliteConnection) -> Self {
        Self {
            wrapped_conn: Arc::new(parking_lot::Mutex::new(conn)),
        }
    }

    // Note: F is a synchronous fn. If it ever becomes async, we need to use
    // tokio::sync::mutex instead of std::sync::Mutex
    pub(crate) fn raw_query<T, F>(&self, fun: F) -> Result<T, diesel::result::Error>
    where
        F: FnOnce(&mut SqliteConnection) -> Result<T, diesel::result::Error>,
    {
        let mut lock = self.wrapped_conn.lock();
        fun(&mut lock)
    }
}

impl fmt::Debug for DbConnectionSync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbConnection")
            .field("wrapped_conn", &"DbConnection")
            .finish()
    }
}
