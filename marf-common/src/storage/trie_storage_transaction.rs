use std::{ops::{Deref, DerefMut}, io::Cursor};

use stacks_common::types::chainstate::TrieHash;

use crate::{MarfTrieId, BlockMap, MarfError, storage::{TrieFile, TrieStorageTransientData}, TrieCache, diagnostics::TrieBenchmark};

use super::{TrieStorageConnection, TrieFileStorage, flush_options::FlushOptions, UncommittedState, TrieRAM};

///
/// TrieStorageTransaction is a pointer to an open TrieFileStorage with an
///   open SQLite transaction. Any storage methods which require a transaction
///   are defined _only_ for this struct (e.g., the flush methods).
///
pub struct TrieStorageTransaction<'a, TTrieId>(pub TrieStorageConnection<'a, TTrieId>) 
    where TTrieId: MarfTrieId;

impl<'a, TTrieId: MarfTrieId> Deref for TrieStorageTransaction<'a, TTrieId> {
    type Target = TrieStorageConnection<'a, TTrieId>;
    fn deref(&self) -> &TrieStorageConnection<'a, TTrieId> {
        &self.0
    }
}

impl<'a, TTrieId: MarfTrieId> DerefMut for TrieStorageTransaction<'a, TTrieId> {
    fn deref_mut(&mut self) -> &mut TrieStorageConnection<'a, TTrieId> {
        &mut self.0
    }
}

impl<'a, TTrieId: MarfTrieId> BlockMap<TTrieId> for TrieStorageTransaction<'a, TTrieId> {

    fn get_block_hash(&self, id: u32) -> Result<TTrieId, MarfError> {
        self.deref().get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&TTrieId, MarfError> {
        self.deref_mut().get_block_hash_caching(id)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.deref().is_block_hash_cached(id)
    }

    fn get_block_id(&self, block_hash: &TTrieId) -> Result<u32, MarfError> {
        self.deref().get_block_id(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &TTrieId) -> Result<u32, MarfError> {
        self.deref_mut().get_block_id_caching(block_hash)
    }
}

impl<'a, TTrieId: MarfTrieId> TrieStorageTransaction<'a, TTrieId> {
    /// reopen this transaction as a read-only marf.
    ///  _does not_ preserve the cur_block/open tip
    pub fn reopen_readonly(&'a mut self) -> Result<TrieFileStorage<TTrieId>, MarfError> {
        let mut db = self.index.reopen_readonly()?;
        let blobs = if self.blobs.is_some() {
            Some(TrieFile::from_db_path(&self.db_path, true)?)
        } else {
            None
        };

        trace!(
            "Make read-only view of TrieStorageTransaction: {}",
            &self.db_path
        );

        let cache = TrieCache::default();

        // TODO: borrow self.uncommitted_writes; don't copy them
        let ret = TrieFileStorage {
            db_path: self.db_path.to_string(),
            index: db.as_mut(),
            blobs,
            cache,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: self.hash_calculation_mode,

            data: TrieStorageTransientData {
                uncommitted_writes: None,
                cur_block: TTrieId::sentinel(),
                cur_block_id: None,

                read_count: 0,
                read_backptr_count: 0,
                read_node_count: 0,
                read_leaf_count: 0,

                write_count: 0,
                write_node_count: 0,
                write_leaf_count: 0,

                trie_ancestor_hash_bytes_cache: None,

                readonly: true,
                unconfirmed: self.unconfirmed(),
            },

            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: self.test_genesis_block.clone(),
        };

        Ok(ret)
    }

    /// Run `cls` with a mutable reference to the inner trie blobs opt.
    fn with_trie_blobs<F, R>(&mut self, cls: F) -> R
    where
        F: FnOnce(&mut Option<&mut TrieFile>) -> R,
    {
        let mut blobs = self.blobs.take();
        let res = cls(&mut blobs);
        self.blobs = blobs;
        res
    }

    /// Inner method for flushing the UncommittedState's TrieRAM to disk.
    fn inner_flush(&mut self, flush_options: FlushOptions<'_, TTrieId>) -> Result<(), MarfError> {
        // save the currently-buffered Trie to disk, and atomically put it into place (possibly to
        // a different block than the one opened, as indicated by final_bhh).
        // Runs once -- subsequent calls are no-ops.
        // Panics on a failure to rename the Trie file into place (i.e. if the the actual commitment
        // fails).
        self.clear_cached_ancestor_hashes_bytes();
        if self.data.readonly {
            return Err(MarfError::ReadOnlyError);
        }
        if let Some((bhh, trie_ram)) = self.data.uncommitted_writes.take() {
            trace!("Buffering block flush started.");
            let mut buffer = Cursor::new(Vec::new());
            trie_ram.dump(self, &mut buffer, &bhh)?;

            // consume the cursor, get the buffer
            let buffer = buffer.into_inner();
            trace!("Buffering block flush finished.");

            debug!("Flush: {} to {}", &bhh, flush_options);

            let block_id = match flush_options {
                FlushOptions::CurrentHeader => {
                    if self.unconfirmed() {
                        return Err(MarfError::UnconfirmedError);
                    }
                    self.with_trie_blobs(|blobs| match blobs {
                        Some(blobs) => blobs.store_trie_blob(self.index, &bhh, &buffer),
                        None => {
                            test_debug!("Stored trie blob {} to db", &bhh);
                            self.index.write_trie_blob(&bhh, &buffer)
                        }
                    })?
                }
                FlushOptions::NewHeader(real_bhh) => {
                    // If we opened a block with a given hash, but want to store it as a block with a *different*
                    // hash, then call this method to update the internal storage state to make it so.  This is
                    // necessary for validating blocks in the blockchain, since the miner will always build a
                    // block whose hash is all 0's (since it can't know the final block hash).  As such, a peer
                    // will process a block as if it's hash is all 0's (in order to validate the state root), and
                    // then use this method to switch over the block hash to the "real" block hash.
                    if self.data.unconfirmed {
                        return Err(MarfError::UnconfirmedError);
                    }
                    if real_bhh != &bhh {
                        // note: this was moved from the block_retarget function
                        //  to avoid stepping on the borrow checker.
                        debug!("Retarget block {} to {}", bhh, real_bhh);
                        // switch over state
                        self.data.retarget_block(real_bhh.clone());
                    }
                    self.with_trie_blobs(|blobs| match blobs {
                        Some(blobs) => blobs.store_trie_blob(self.index, real_bhh, &buffer),
                        None => {
                            test_debug!("Stored trie blob {} to db", real_bhh);
                            self.index.write_trie_blob(real_bhh, &buffer)
                        }
                    })?
                }
                FlushOptions::MinedTable(real_bhh) => {
                    if self.unconfirmed() {
                        return Err(MarfError::UnconfirmedError);
                    }
                    self.index.write_trie_blob_to_mined(real_bhh, &buffer)?
                }
                FlushOptions::UnconfirmedTable => {
                    if !self.unconfirmed() {
                        return Err(MarfError::UnconfirmedError);
                    }
                    self.index.write_trie_blob_to_unconfirmed(&bhh, &buffer)?
                }
            };

            self.index.drop_lock(&bhh)?;

            debug!("Flush: identifier of {} is {}", flush_options, block_id);
        }

        Ok(())
    }

    /// Flush uncommitted state to disk.
    pub fn flush(&mut self) -> Result<(), MarfError> {
        if self.data.unconfirmed {
            self.inner_flush(FlushOptions::UnconfirmedTable)
        } else {
            self.inner_flush(FlushOptions::CurrentHeader)
        }
    }

    /// Flush uncommitted state to disk, but under the given block hash.
    pub fn flush_to(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        self.inner_flush(FlushOptions::NewHeader(bhh))
    }

    /// Flush uncommitted state to disk for a mined block (i.e. not part of the chainstate, and not
    /// an ancestor of any block), and do so under a given block hash.
    pub fn flush_mined(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        self.inner_flush(FlushOptions::MinedTable(bhh))
    }

    /// Drop the uncommitted state and any associated cached state.
    pub fn drop_extending_trie(&mut self) {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.readonly {
            if let Some((ref bhh, _)) = self.data.uncommitted_writes.take() {
                self.index.drop_lock(bhh)
                    .expect("Corruption: Failed to drop the extended trie lock");
            }
            self.data.uncommitted_writes = None;
            self.data.clear_block_id();
            self.data.trie_ancestor_hash_bytes_cache = None;
        }
    }

    /// Drop the unconfirmed state and uncommitted state.
    pub fn drop_unconfirmed_trie(&mut self, bhh: &TTrieId) {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.readonly && self.data.unconfirmed {
            self.index.drop_unconfirmed_trie(bhh)
                .expect("Corruption: Failed to drop unconfirmed trie");
            self.index.drop_lock(bhh)
                .expect("Corruption: Failed to drop the extended trie lock");
            self.data.uncommitted_writes = None;
            self.data.clear_block_id();
            self.data.trie_ancestor_hash_bytes_cache = None;
        }
    }

    /// Seal the inner uncommitted TrieRAM and return the MARF root hash.
    /// Only works if there's an uncommitted TrieRAM extension; panics if not.
    pub fn seal(&mut self) -> Result<TrieHash, MarfError> {
        if let Some((bhh, trie_ram)) = self.data.uncommitted_writes.take() {
            let sealed_trie_ram = trie_ram.seal(self)?;
            let root_hash = match sealed_trie_ram {
                UncommittedState::Sealed(_, root_hash) => root_hash.clone(),
                _ => {
                    unreachable!("FATAL: .seal() did not make a sealed trieram");
                }
            };
            self.data.uncommitted_writes = Some((bhh, sealed_trie_ram));
            Ok(root_hash)
        } else {
            panic!("FATAL: tried to a .seal() a trie that was not extended");
        }
    }

    /// Extend the forest of Tries to include a new confirmed block.
    /// Fails if the block already exists, or if the storage is read-only, or open
    /// only for unconfirmed state.
    pub fn extend_to_block(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        self.clear_cached_ancestor_hashes_bytes();
        if self.data.readonly {
            return Err(MarfError::ReadOnlyError);
        }
        if self.data.unconfirmed {
            return Err(MarfError::UnconfirmedError);
        }

        if self.get_block_id_caching(bhh).is_ok() {
            warn!("Block already exists: {}", &bhh);
            return Err(MarfError::ExistsError);
        }

        self.flush()?;

        let size_hint = match self.data.uncommitted_writes {
            Some((_, ref trie_storage)) => 2 * trie_storage.size_hint(),
            None => 1024, // don't try to guess _byte_ allocation here.
        };

        let trie_buf = TrieRAM::new(bhh, size_hint, &self.data.cur_block);

        // place a lock on this block, so we can't extend to it again
        if !self.index.lock_bhh_for_extension(bhh, false)? {
            warn!("Block already extended: {}", &bhh);
            return Err(MarfError::ExistsError);
        }

        self.switch_trie(bhh, UncommittedState::RW(trie_buf));
        Ok(())
    }

    /// Extend the forest of Tries to include a new unconfirmed block.
    /// If the unconfirmed block (bhh) already exists, then load up its trie as the uncommitted_writes
    /// trie.
    pub fn extend_to_unconfirmed_block(&mut self, bhh: &TTrieId) -> Result<bool, MarfError> {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.unconfirmed {
            return Err(MarfError::UnconfirmedError);
        }

        self.flush()?;

        // try to load up the trie
        let (trie_buf, created, unconfirmed_block_id) =
            if let Some(block_id) = self.index.get_unconfirmed_block_identifier(bhh)? {
                debug!("Reload unconfirmed trie {} ({})", bhh, block_id);

                // restore trie
                let mut fd = self.index.open_trie_blob(block_id)?;

                test_debug!("Unconfirmed trie block ID for {} is {}", bhh, block_id);
                (TrieRAM::load(&mut fd, bhh)?, false, Some(block_id))
            } else {
                debug!("Instantiate unconfirmed trie {}", bhh);

                // new trie
                let size_hint = match self.data.uncommitted_writes {
                    Some((_, ref trie_storage)) => 2 * trie_storage.size_hint(),
                    None => 1024, // don't try to guess _byte_ allocation here.
                };

                (
                    TrieRAM::new(bhh, size_hint, &self.data.cur_block),
                    true,
                    None,
                )
            };

        // place a lock on this block, so we can't extend to it again
        if !self.index.lock_bhh_for_extension(bhh, true)? {
            warn!("Block already extended: {}", &bhh);
            return Err(MarfError::ExistsError);
        }

        self.unconfirmed_block_id = unconfirmed_block_id;
        self.switch_trie(bhh, UncommittedState::RW(trie_buf));
        Ok(created)
    }

    /// Clear out the underlying storage.
    pub fn format(&mut self) -> Result<(), MarfError> {
        if self.data.readonly {
            return Err(MarfError::ReadOnlyError);
        }

        debug!("Format TrieFileStorage");

        // blow away db
        self.index.format()?;

        match self.data.uncommitted_writes {
            Some((_, ref mut trie_storage)) => trie_storage.format()?,
            None => {}
        };

        self.data.set_block(TTrieId::sentinel(), None);

        self.data.uncommitted_writes = None;
        self.clear_cached_ancestor_hashes_bytes();

        Ok(())
    }

    /*pub fn sqlite_tx(&self) -> &Transaction<'a> {
        match &self.0.db {
            SqliteConnection::Tx(ref tx) => tx,
            SqliteConnection::ConnRef(_) => {
                unreachable!(
                    "BUG: Constructed TrieStorageTransaction with a bare sqlite connection ref."
                );
            }
        }
    }

    pub fn sqlite_tx_mut(&mut self) -> &mut Transaction<'a> {
        match &mut self.0.db {
            SqliteConnection::Tx(ref mut tx) => tx,
            SqliteConnection::ConnRef(_) => {
                unreachable!(
                    "BUG: Constructed TrieStorageTransaction with a bare sqlite connection ref."
                );
            }
        }
    }*/

    pub fn commit_tx(self) {
        self.index.commit_transaction();
    }

    pub fn rollback(mut self) {
        self.index.rollback_transaction();
    }
}