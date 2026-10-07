//! Bounded local reads. Cursors expire when the recovered wallet view changes.
//!
//! Each page decodes at most 256 records from a database snapshot, using a
//! range seek and one raw lookahead. RocksDB streams that range; backend
//! buffering (such as the test-only in-memory database) is outside this API's
//! control.
use fedimint_core::db::{
    DatabaseKey, DatabaseKeyPrefix, DatabaseRecord, DatabaseValue, IDatabaseTransactionOpsCore,
    WithDecoders,
};

use super::*;

pub const MAX_WALLET_PAGE_SIZE: usize = 256;

/// Opaque, local continuation token. It can be serialized across application
/// restarts but must be discarded after `StaleCursor`. It is not a recovery
/// backup.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletCursor {
    revision: [u8; 32],
    position: Position,
}
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
enum Position {
    Contract(OutPoint),
    History(u64, u64),
}
impl Position {
    fn key(&self) -> Vec<u8> {
        match self {
            Self::Contract(point) => DatabaseKeyPrefix::to_bytes(&db::ContractKey(*point)),
            Self::History(session, item) => {
                DatabaseKeyPrefix::to_bytes(&db::HistoryKey(*session, *item))
            }
        }
    }
}
#[derive(Debug)]
pub struct WalletPage<T> {
    pub entries: Vec<T>,
    /// `None` means the end of this view. Never reuse a cursor with a different
    /// collection or wallet; start over if concurrent sync changes the view.
    pub next: Option<WalletCursor>,
}
#[derive(Debug, thiserror::Error)]
pub enum PageError {
    #[error("page size must be between 1 and {MAX_WALLET_PAGE_SIZE}")]
    InvalidLimit,
    #[error("wallet view changed; restart the listing")]
    StaleCursor,
    #[error("cursor belongs to a different collection")]
    WrongCollection,
}

impl WalletStore {
    /// Read all contract records, including spent ones, in database outpoint
    /// order. Filtering a returned page locally keeps each read bounded.
    /// `limit` must be in `1..=MAX_WALLET_PAGE_SIZE`. Pass `None` for the first
    /// page, then `page.next` until it is `None`. On
    /// [`PageError::StaleCursor`], discard previously accumulated pages and
    /// restart from `None`.
    pub async fn contracts_page(
        &self,
        cursor: Option<&WalletCursor>,
        limit: usize,
    ) -> anyhow::Result<WalletPage<(OutPoint, WalletContract)>> {
        let page = self
            .page::<db::ContractKey>(cursor, limit, |key| Position::Contract(key.0))
            .await?;
        Ok(WalletPage {
            entries: page
                .entries
                .into_iter()
                .map(|(key, value)| (key.0, value))
                .collect(),
            next: page.next,
        })
    }

    /// Read confirmed interactions in ascending (session, item) order. This
    /// includes terminal spends and sender-only receipts, just like `history`.
    /// Limits and cursor handling are the same as [`Self::contracts_page`].
    pub async fn history_page(
        &self,
        cursor: Option<&WalletCursor>,
        limit: usize,
    ) -> anyhow::Result<WalletPage<HistoryEntry>> {
        let page = self
            .page::<db::HistoryKey>(cursor, limit, |key| Position::History(key.0, key.1))
            .await?;
        Ok(WalletPage {
            entries: page.entries.into_iter().map(|(_, value)| value).collect(),
            next: page.next,
        })
    }

    async fn page<K: DatabaseKey + DatabaseRecord>(
        &self,
        cursor: Option<&WalletCursor>,
        limit: usize,
        position: impl Fn(&K) -> Position,
    ) -> anyhow::Result<WalletPage<(K, K::Value)>> {
        if !(1..=MAX_WALLET_PAGE_SIZE).contains(&limit) {
            return Err(PageError::InvalidLimit.into());
        }
        let mut tx = self.db.begin_transaction_nc().await;
        let revision = tx
            .get_value(&db::ViewRevisionKey)
            .await
            .expect("wallet initialized");
        let start = if let Some(cursor) = cursor {
            if cursor.revision != revision {
                return Err(PageError::StaleCursor.into());
            }
            let mut key = cursor.position.key();
            if key[0] != K::DB_PREFIX {
                return Err(PageError::WrongCollection.into());
            }
            // Canonical keys in each collection are prefix-free. Appending a
            // zero seeks immediately after this exact key, even at u64::MAX.
            key.push(0);
            key
        } else {
            vec![K::DB_PREFIX]
        };
        // BigSize integers sort numerically, so history keys sort by (session, item).
        let end = [K::DB_PREFIX
            .checked_add(1)
            .expect("wallet prefix below 255")];
        let decoders = tx.decoders().clone();
        let mut rows = tx
            .raw_find_by_range(start.as_slice()..end.as_slice())
            .await?;
        let mut entries = Vec::with_capacity(limit);
        let mut last = None;
        while entries.len() < limit {
            let Some((key, value)) = rows.next().await else {
                break;
            };
            let key = K::from_bytes(&key, &decoders)?;
            let value = K::Value::from_bytes(&value, &decoders)?;
            last = Some(position(&key));
            entries.push((key, value));
        }
        // One bounded lookahead avoids an unnecessary empty final page.
        let next = if entries.len() == limit && rows.next().await.is_some() {
            Some(WalletCursor {
                revision,
                position: last.expect("full nonempty page"),
            })
        } else {
            None
        };
        Ok(WalletPage { entries, next })
    }
}
