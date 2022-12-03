use crate::storage::TrieIndexProvider;

pub struct SqliteIndexProvider;

impl TrieIndexProvider for SqliteIndexProvider {
    fn new() -> Self {
        todo!()
    }

    fn get_block_hash<T: crate::MarfTrieId>(&self, local_id: u32) -> Result<T, crate::MarfError> {
        todo!()
    }

    fn get_block_identifier<T: crate::MarfTrieId>(&self, bhh: &T) -> Result<u32, crate::MarfError> {
        todo!()
    }
}