use crate::batch::BatchItem;
use crate::{
    BatchDb, Database, DatabaseError, DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DbIter,
    DecodingError, PrefixSearchable, Transactional,
};
use sled::transaction::TransactionError;
use sled::IVec;
use tracing::{error, trace};

impl Database for sled::transaction::TransactionalTree {
    type Err = sled::transaction::ConflictableTransactionError<DecodingError>;

    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        match self.insert(key.to_bytes(), value.to_bytes())? {
            Some(old_val_bytes) => Ok(Some(V::from_bytes(&old_val_bytes)?)),
            None => Ok(None),
        }
    }

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.get(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.remove(key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }
}

impl Database for sled::Tree {
    type Err = DatabaseError;

    fn insert_entry<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        match self.insert(key.to_bytes(), value.to_bytes())? {
            Some(old_val_bytes) => Ok(Some(V::from_bytes(&old_val_bytes)?)),
            None => Ok(None),
        }
    }

    fn get_value<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.get(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }

    fn remove_entry<K, V>(&self, key: &K) -> Result<Option<V>, Self::Err>
    where
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let key_bytes = key.to_bytes();
        let value_bytes = match self.remove(&key_bytes)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(V::from_bytes(&value_bytes)?))
    }
}

impl PrefixSearchable for sled::Tree {
    type Bytes = IVec;
    type IterErr = sled::Error;
    type Iter = sled::Iter;

    fn find_by_prefix<KP, K, V>(
        &self,
        key_prefix: &KP,
    ) -> DbIter<Self::Iter, Self::Bytes, Self::IterErr, K, V>
    where
        KP: DatabaseKeyPrefix,
        K: DatabaseKey,
        V: DatabaseValue,
    {
        let prefix_bytes = key_prefix.to_bytes();
        DbIter {
            iter: self.scan_prefix(&prefix_bytes),
            _pd: Default::default(),
        }
    }
}

impl Transactional for sled::Tree {
    type TransactionError = sled::transaction::TransactionError<DecodingError>;
    type Transaction = sled::transaction::TransactionalTree;

    fn transaction<F, A>(&self, f: F) -> sled::transaction::TransactionResult<A, DecodingError>
    where
        F: Fn(
            &Self::Transaction,
        ) -> sled::transaction::ConflictableTransactionResult<A, DecodingError>,
    {
        self.transaction(f)
    }
}

impl BatchDb for sled::Tree {
    fn apply_batch<'b, B>(&self, batch: B) -> Result<(), DatabaseError>
    where
        B: IntoIterator<Item = &'b BatchItem> + 'b,
        B::IntoIter: Clone,
    {
        let batch_iter = batch.into_iter();

        self.transaction(|t| {
            for change in batch_iter.clone() {
                match change {
                    BatchItem::InsertNewElement(element) => {
                        if t.insert(element.key.to_bytes(), element.value.to_bytes())?
                            .is_some()
                        {
                            error!("Database replaced element! This should not happen!");
                            trace!("Problematic key: {:?}", element.key);
                        }
                    }
                    BatchItem::InsertElement(element) => {
                        t.insert(element.key.to_bytes(), element.value.to_bytes())?;
                    }
                    BatchItem::DeleteElement(key) => {
                        if t.remove(key.to_bytes())?.is_none() {
                            error!("Database deleted absent element! This should not happen!");
                            trace!("Problematic key: {:?}", key);
                        }
                    }
                    BatchItem::MaybeDeleteElement(key) => {
                        t.remove(key.to_bytes())?;
                    }
                }
            }

            Ok(())
        })
        .map_err(|e: TransactionError| DatabaseError::DbError(e.into()))
    }
}

impl From<DecodingError> for sled::transaction::ConflictableTransactionError<DecodingError> {
    fn from(e: DecodingError) -> Self {
        sled::transaction::ConflictableTransactionError::Abort(e)
    }
}

impl From<sled::Error> for DatabaseError {
    fn from(e: sled::Error) -> Self {
        DatabaseError::DbError(e.into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_basic_rw() {
        let path = tempdir::TempDir::new("fcb-sled-test").unwrap();
        let db = sled::open(path).unwrap();
        crate::tests::test_db_impl(&db.open_tree("default").unwrap());
    }
}
