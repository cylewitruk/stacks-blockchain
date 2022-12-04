use crate::{MarfTrieId, storage::{TrieIndexProvider, TrieStorageConnectionTrait}};

pub struct SqliteTrieStorageConnection<TTrieId: MarfTrieId, TIndex: TrieIndexProvider>;

impl<TTrieId: MarfTrieId, TIndex: TrieIndexProvider> TrieStorageConnectionTrait<TTrieId, TIndex> for SqliteTrieStorageConnection<TTrieId, TIndex> {
    
}

