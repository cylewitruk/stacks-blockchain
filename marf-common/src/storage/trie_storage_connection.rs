use std::{
    io::Write
};

#[cfg(test)]
use std::collections::HashMap;

use stacks_common::{
    types::chainstate::{TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE, TRIEHASH_ENCODED_SIZE}, 
    util::hash::to_hex
};

use crate::{
    MarfTrieId, BlockMap, MarfError, TrieCache, TrieHashExtension,
    tries::{
        TrieHashCalculationMode, 
        TriePtr, 
        nodes::{
            TrieNodeID, 
            TrieNodeType, 
            TrieNode
        }
    }, 
    diagnostics::TrieBenchmark, 
    utils::Utils, 
    storage::{
        TrieFileNodeHashReader, 
        TrieHashMapCursor, 
        TrieCursor
    }
};

use super::{TrieStorageTransientData, TrieIndexProvider, TrieFile, UncommittedState, node_hash_reader::NodeHashReader};

///
///  TrieStorageConnection is a pointer to an open TrieFileStorage,
///    with either a SQLite &Connection (non-mut, so it cannot start a TX)
///    or a Transaction. Mutations on TrieStorageConnection's `data` field
///    propagate to the TrieFileStorage that created the connection.
///  This is the main interface to the storage methods, and defines most
///    of the storage functionality.
///
pub struct TrieStorageConnection<'a, TTrieId>
    where TTrieId: MarfTrieId
{
    pub db_path: &'a str,
    pub index: &'a dyn TrieIndexProvider<TTrieId>,
    pub blobs: Option<&'a mut TrieFile>,
    pub data: &'a mut TrieStorageTransientData<TTrieId>,
    pub cache: &'a mut TrieCache<TTrieId>,
    pub bench: &'a mut TrieBenchmark,
    pub hash_calculation_mode: TrieHashCalculationMode,

    /// row ID of a trie that represents unconfirmed state (i.e. trie state that will never become
    /// part of the MARF, but nevertheless represents a persistent scratch space).  If this field
    /// is Some(..), then the storage connection here was used to (re-)open an unconfirmed trie
    /// (via `open_unconfirmed()` or `open_block()` when `self.unconfirmed()` is `true`), or used
    /// to create an unconfirmed trie (via `extend_to_unconfirmed_block()`).
    pub unconfirmed_block_id: Option<u32>,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: &'a mut Option<TTrieId>,
}

impl<'a, TTrieId> TrieStorageConnection<'a, TTrieId> 
    where 
        TTrieId: MarfTrieId
{
    fn new(
        db_path: &'a str, 
        index: &'a dyn TrieIndexProvider<TTrieId>, 
        blobs: Option<&'a mut TrieFile>,
        data: &'a mut TrieStorageTransientData<TTrieId>,
        cache: &'a mut TrieCache<TTrieId>,
        bench: &'a mut TrieBenchmark,
        hash_calculation_mode: TrieHashCalculationMode,
        unconfirmed_block_id: Option<u32>,
        #[cfg(test)]
        test_genesis_block: &'a mut Option<TTrieId>
    ) -> Self {
        TrieStorageConnection { 
            db_path, 
            index, 
            blobs, 
            data, 
            cache, 
            bench, 
            hash_calculation_mode, 
            unconfirmed_block_id,
            #[cfg(test)]
            test_genesis_block
        }
    }
}

impl<'a, TTrieId: MarfTrieId> BlockMap<TTrieId> for TrieStorageConnection<'a, TTrieId> {
    fn get_block_hash(&self, id: u32) -> Result<TTrieId, MarfError> {
        //trie_sql::get_block_hash(&self.db, id)
        self.index.get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&TTrieId, MarfError> {
        if !self.is_block_hash_cached(id) {
            let block_hash = self.get_block_hash(id)?;
            self.cache.store_block_hash(id, block_hash.clone());
        }
        self.cache.ref_block_hash(id).ok_or(MarfError::NotFoundError)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &TTrieId) -> Result<u32, MarfError> {
        //trie_sql::get_block_identifier(&self.db, block_hash)
        self.index.get_block_identifier(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &TTrieId) -> Result<u32, MarfError> {
        // don't use the cache if we're unconfirmed
        if self.data.unconfirmed {
            self.get_block_id(block_hash)
        } else {
            if let Some(block_id) = self.cache.load_block_id(block_hash) {
                Ok(block_id)
            } else {
                let block_id = self.get_block_id(block_hash)?;
                self.cache.store_block_hash(block_id, block_hash.clone());
                Ok(block_id)
            }
        }
    }
}

impl<'a, TTrieId: MarfTrieId> TrieStorageConnection<'a, TTrieId> {
    pub fn readonly(&self) -> bool {
        self.data.readonly
    }

    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
    }

    pub fn set_cached_ancestor_hashes_bytes(&mut self, bhh: &TTrieId, bytes: Vec<TrieHash>) {
        self.data.trie_ancestor_hash_bytes_cache = Some((bhh.clone(), bytes));
    }

    pub fn clear_cached_ancestor_hashes_bytes(&mut self) {
        self.data.trie_ancestor_hash_bytes_cache = None;
    }

    pub fn get_root_hash_at(&mut self, tip: &TTrieId) -> Result<TrieHash, MarfError> {
        let cur_block_hash = self.get_cur_block();

        self.open_block(tip)?;
        let root_hash_res = Utils::read_root_hash(self);

        // restore
        self.open_block(&cur_block_hash)?;
        root_hash_res
    }

    pub fn check_cached_ancestor_hashes_bytes(&mut self, bhh: &TTrieId) -> Option<Vec<TrieHash>> {
        if let Some((ref cached_bhh, ref cached_bytes)) = self.data.trie_ancestor_hash_bytes_cache {
            if cached_bhh == bhh {
                return Some(cached_bytes.clone());
            }
        }
        None
    }

    

    #[cfg(test)]
    pub fn stats(&mut self) -> (u64, u64) {
        let r = self.data.read_count;
        let w = self.data.write_count;
        self.data.read_count = 0;
        self.data.write_count = 0;
        (r, w)
    }

    #[cfg(test)]
    pub fn node_stats(&mut self) -> (u64, u64, u64) {
        let nr = self.data.read_node_count;
        let br = self.data.read_backptr_count;
        let nw = self.data.write_node_count;

        self.data.read_node_count = 0;
        self.data.read_backptr_count = 0;
        self.data.write_node_count = 0;

        (nr, br, nw)
    }

    #[cfg(test)]
    pub fn leaf_stats(&mut self) -> (u64, u64) {
        let lr = self.data.read_leaf_count;
        let lw = self.data.write_leaf_count;

        self.data.read_leaf_count = 0;
        self.data.write_leaf_count = 0;

        (lr, lw)
    }

    /// Read the Trie root node's hash from the block table.
    #[cfg(test)]
    pub fn read_block_root_hash(&mut self, bhh: &TTrieId) -> Result<TrieHash, MarfError> {
        let root_hash_ptr = TriePtr::new(
            TrieNodeID::Node256 as u8,
            0,
            TrieStorageConnection::<TTrieId>::root_ptr_disk(),
        );
        if let Some(blobs) = self.blobs.as_mut() {
            // stored in a blobs file
            blobs.get_node_hash_bytes_by_bhh(self.index, bhh, &root_hash_ptr)
        } else {
            // stored to DB
            self.index.get_node_hash_bytes_by_bhh(bhh, &root_hash_ptr)
        }
    }

    #[cfg(test)]
    fn inner_read_persisted_root_to_blocks(&mut self) -> Result<HashMap<TrieHash, TTrieId>, MarfError> {
        let ret = match self.blobs.as_mut() {
            Some(blobs) => {
                HashMap::from_iter(blobs.read_all_block_hashes_and_roots(self.index)?.into_iter())
            }
            None => {
                HashMap::from_iter(self.index.read_all_block_hashes_and_roots()?.into_iter())
            }
        };
        Ok(ret)
    }

    /// Generate a mapping between Trie root hashes and the blocks that contain them
    #[cfg(test)]
    pub fn read_root_to_block_table(&mut self) -> Result<HashMap<TrieHash, TTrieId>, MarfError> {


        let mut ret = self.inner_read_persisted_root_to_blocks()?;
        let uncommitted_writes = match self.data.uncommitted_writes.take() {
            Some((bhh, trie_ram)) => {
                let ptr = TriePtr::new(Utils::set_backptr(TrieNodeID::Node256 as u8), 0, 0);

                let root_hash = trie_ram.read_node_hash(&ptr)?;

                ret.insert(root_hash.clone(), bhh.clone());
                Some((bhh, trie_ram))
            }
            _ => None,
        };

        self.data.uncommitted_writes = uncommitted_writes;

        Ok(ret)
    }

    /// internal procedure for locking a trie hash for work
    pub (in crate::storage) fn switch_trie(&mut self, bhh: &TTrieId, trie_buf: UncommittedState<TTrieId>) {
        trace!("Extended from {} to {}", &self.data.cur_block, bhh);

        // update internal structures
        self.data.set_block(bhh.clone(), None);
        self.clear_cached_ancestor_hashes_bytes();

        self.data.uncommitted_writes = Some((bhh.clone(), trie_buf));
    }

    /// Is the given block represented in either the confirmed or unconfirmed block tables?
    /// The mined table is ignored.
    pub fn has_block(&self, bhh: &TTrieId) -> Result<bool, MarfError> {
        Ok(self.has_confirmed_block(bhh)? || self.has_unconfirmed_block(bhh)?)
    }

    /// Used for providing a option<block identifier> when re-opening a block --
    ///   because the previously open block may have been the uncommitted_writes block,
    ///   id may have been None.
    pub fn open_block_maybe_id(&mut self, bhh: &TTrieId, id: Option<u32>) -> Result<(), MarfError> {
        match id {
            Some(id) => self.open_block_known_id(bhh, id),
            None => self.open_block(bhh),
        }
    }

    /// Used for providing a block identifier when opening a block -- usually used
    ///   when following a backptr, which stores the block identifier directly.
    pub fn open_block_known_id(&mut self, bhh: &TTrieId, id: u32) -> Result<(), MarfError> {
        trace!(
            "open_block_known_id({},{}) (unconfirmed={:?},{})",
            bhh,
            id,
            &self.unconfirmed_block_id,
            self.unconfirmed()
        );
        if *bhh == self.data.cur_block && self.data.cur_block_id.is_some() {
            // no-op
            return Ok(());
        }

        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if uncommitted_bhh == bhh {
                panic!("BUG: passed id of a currently building block");
            }
        }

        // opening a different Trie than the one we're extending
        self.data.set_block(bhh.clone(), Some(id));
        Ok(())
    }

    /// Return the block_identifier / row_id for a given bhh. If that bhh
    ///  is currently being extended, return None, since the row_id won't
    ///  be known until the extended trie is flushed.
    pub fn get_block_identifier(&mut self, bhh: &TTrieId) -> Option<u32> {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if bhh == uncommitted_bhh {
                return None;
            }
        }

        self.get_block_id_caching(bhh).ok()
    }

    /// Get the currently-open block identifier (its row ID)
    pub fn get_cur_block_identifier(&mut self) -> Result<u32, MarfError> {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if &self.data.cur_block == uncommitted_bhh {
                return Err(MarfError::RequestedIdentifierForExtensionTrie);
            }
        }

        self.data.cur_block_id.ok_or_else(|| MarfError::NotOpenedError)
    }

    /// Get the currently-open block hash
    pub fn get_cur_block(&self) -> TTrieId {
        self.data.cur_block.clone()
    }

    /// Get the currently-open block hash and block ID (row ID)
    pub fn get_cur_block_and_id(&self) -> (TTrieId, Option<u32>) {
        (self.data.cur_block.clone(), self.data.cur_block_id.clone())
    }

    /// Get the block hash of a given block ID (i.e. row ID)
    pub fn get_block_from_local_id(&mut self, local_id: u32) -> Result<&TTrieId, MarfError> {
        let res = self.get_block_hash_caching(local_id);
        res
    }

    /// Get the TriePtr::ptr() value for the root node in the currently-open block.
    pub fn root_ptr(&self) -> u32 {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if &self.data.cur_block == uncommitted_bhh {
                return 0;
            }
        }

        TrieStorageConnection::<TTrieId>::root_ptr_disk()
    }

    /// Get a TriePtr to the currently-open block's trie's root node.
    pub fn root_trieptr(&self) -> TriePtr {
        TriePtr::new(TrieNodeID::Node256 as u8, 0, self.root_ptr())
    }

    /// Get the TriePtr::ptr() value for a trie's root node if the node is stored to disk.
    pub fn root_ptr_disk() -> u32 {
        // first 32 bytes are the block parent hash
        //   next 4 are the identifier
        (BLOCK_HEADER_HASH_ENCODED_SIZE as u32) + 4
    }

    pub (crate) fn has_confirmed_block(&self, bhh: &TTrieId) -> Result<bool, crate::MarfError> {
        match self.index.get_confirmed_block_identifier(bhh) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn has_unconfirmed_block(&self, bhh: &TTrieId) -> Result<bool, crate::MarfError> {
        match self.index.get_unconfirmed_block_identifier(bhh) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Open a trie's block, identified by `bhh`.  Updates the internal state to point to it, so
    /// that all node reads will occur relative to it.
    pub fn open_block(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        trace!(
            "open_block({}) (unconfirmed={:?},{})",
            bhh,
            &self.unconfirmed_block_id,
            self.unconfirmed()
        );
        self.bench.open_block_start();

        if *bhh == self.data.cur_block && self.data.cur_block_id.is_some() {
            // no-op
            if self.unconfirmed() {
                if self.data.cur_block_id
                    == self.index.get_unconfirmed_block_identifier(bhh)?
                {
                    test_debug!(
                        "{} unconfirmed trie block ID is {:?}",
                        bhh,
                        &self.data.cur_block_id
                    );
                    self.unconfirmed_block_id = self.data.cur_block_id.clone();
                }
            }

            self.bench.open_block_finish(true);
            return Ok(());
        }

        let sentinel = TTrieId::sentinel();
        if *bhh == sentinel {
            // just reset to newly opened state
            // did we write to the sentinel?
            let block_id_opt = self.get_block_id_caching(bhh).ok();
            self.data.set_block(sentinel, block_id_opt);
            self.bench.open_block_finish(true);
            return Ok(());
        }

        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if uncommitted_bhh == bhh {
                // nothing to do -- we're already ready.
                // just clear out.
                if self.unconfirmed() {
                    if self.data.cur_block_id
                        == self.index.get_unconfirmed_block_identifier(bhh)?
                    {
                        test_debug!(
                            "{} unconfirmed trie block ID is {:?}",
                            bhh,
                            &self.data.cur_block_id
                        );
                        self.unconfirmed_block_id = self.data.cur_block_id.clone();
                    }
                }
                self.data.set_block(bhh.clone(), None);
                self.bench.open_block_finish(true);
                return Ok(());
            }
        }

        if self.unconfirmed() {
            if let Some(block_id) = self.index.get_unconfirmed_block_identifier(bhh)? {
                // this is an unconfirmed trie being opened
                self.data.set_block(bhh.clone(), Some(block_id));
                self.bench.open_block_finish(false);

                // reads to this block will hit sqlite
                test_debug!("{} unconfirmed trie block ID is {}", bhh, block_id);
                self.unconfirmed_block_id = Some(block_id);
                return Ok(());
            }
        }

        // opening a different Trie than the one we're extending
        let block_id = self.get_block_id_caching(bhh).map_err(|e| {
            test_debug!("Failed to open {:?}: {:?}", bhh, e);
            e
        })?;

        self.data.set_block(bhh.clone(), Some(block_id));
        self.bench.open_block_finish(false);
        Ok(())
    }

    /// Read a node's children's hashes into the provided <Write> implementation.
    /// This only works for intermediate nodes and leafs (the latter of which have no children).
    ///
    /// This method is designed to only access hashes that are either (1) in this Trie, or (2) in
    /// RAM already (i.e. as part of the block map)
    ///
    /// This means that the hash of a node that is in a previous Trie will _not_ be its
    /// hash (as that would require a disk access), but would instead be the root hash of the Trie
    /// that contains it.  While this makes the Merkle proof construction a bit more complicated,
    /// it _significantly_ improves the performance of this method (which is crucial since this is on
    /// the write path, which must be as short as possible).
    ///
    /// Rules:
    /// If a node is empty, pass in an empty hash.
    /// If a node is in this Trie, pass its hash.
    /// If a node is in a previous Trie, pass the root hash of its Trie.
    ///
    /// On err, S may point to a prior block.  The caller should call s.open(...) if an error
    /// occurs.
    ///
    /// NOTE: this method should only be called if `hash_calculation_mode` is set to
    /// `TrieHashCalculationMode::All` or `TrieHashCalculationMode::Immediate`.  There is no need
    /// to call if the hash mode is `::Deferred`.  The only way this gets called while not in
    /// `::Deferred` mode is when generating a Merkle proof.
    pub fn write_children_hashes<W: Write>(
        &mut self,
        node: &TrieNodeType,
        w: &mut W,
    ) -> Result<(), MarfError> {
        if self.data.readonly {
            return Err(MarfError::ReadOnlyError);
        }

        trace!("write_children_hashes for {:?}", node);

        let mut map = TrieHashMapCursor {
            index: self.index,
            cache: &mut self.cache,
            unconfirmed: self.data.unconfirmed,
        };

        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            if &self.data.cur_block == uncommitted_bhh {
                // storage currently points to uncommitted state
                let start_time = self.bench.write_children_hashes_start();
                let res = TrieStorageConnection::inner_write_children_hashes(
                    uncommitted_trie.trie_ram_mut(),
                    &mut map,
                    node,
                    w,
                    &mut self.bench,
                );
                self.bench.write_children_hashes_finish(start_time, true);
                return res;
            }
        }

        // storage points to committed state
        if let Some(blobs) = self.blobs.as_mut() {
            // tries stored on file
            let start_time = self.bench.write_children_hashes_start();
            let block_id = self.data.cur_block_id.ok_or_else(|| {
                error!("Failed to get cur block as hash reader");
                MarfError::NotFoundError
            })?;
            let mut cursor = TrieFileNodeHashReader::new(self.index, blobs, block_id);
            let res = TrieStorageConnection::<TTrieId>::inner_write_children_hashes(
                &mut cursor,
                &mut map,
                node,
                w,
                &mut self.bench,
            );
            self.bench.write_children_hashes_finish(start_time, false);
            res
        } else {
            // tries stored in DB
            let start_time = self.bench.write_children_hashes_start();
            let mut cursor = TrieCursor {
                index: self.index,
                block_id: self.data.cur_block_id.ok_or_else(|| {
                    error!("Failed to get cur block as hash reader");
                    MarfError::NotFoundError
                })?,
            };
            let res = TrieStorageConnection::inner_write_children_hashes(
                &mut cursor,
                &mut map,
                node,
                w,
                &mut self.bench,
            );
            self.bench.write_children_hashes_finish(start_time, false);
            res
        }
    }

    /// Inner method for calculating a node's hash, by hashing its children.
    fn inner_write_children_hashes<W: Write, H: NodeHashReader, M: BlockMap<TTrieId>>(
        hash_reader: &mut H,
        map: &mut M,
        node: &TrieNodeType,
        w: &mut W,
        bench: &mut TrieBenchmark,
    ) -> Result<(), MarfError> {
        trace!("inner_write_children_hashes begin for node {:?}:", &node);
        for ptr in node.ptrs().iter() {
            if ptr.id() == TrieNodeID::Empty as u8 {
                // hash of empty string
                let start_time = bench.write_children_hashes_empty_start();

                trace!(
                    "inner_write_children_hashes for node {:?}: {:?} empty",
                    &node,
                    &ptr
                );
                w.write_all(TrieHash::from_data(&[]).as_bytes())?;

                bench.write_children_hashes_empty_finish(start_time);
            } else if !Utils::is_backptr(ptr.id()) {
                // hash is in the same block as this node
                let start_time = bench.write_children_hashes_same_block_start();

                let mut buf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
                hash_reader.read_node_hash_bytes(ptr, &mut buf)?;
                trace!(
                    "inner_write_children_hashes for node {:?}: {:?} same block {}",
                    &node,
                    &ptr,
                    &to_hex(&buf)
                );
                w.write_all(&buf[..])?;

                bench.write_children_hashes_same_block_finish(start_time);
            } else {
                // hash is in a different block altogether, so we just use the ancestor block hash.  The
                // ptr.ptr() value points to the actual node in the ancestor block.
                let start_time = bench.write_children_hashes_ancestor_block_start();

                let block_hash = map.get_block_hash_caching(ptr.back_block())?;
                trace!(
                    "inner_write_children_hashes for node {:?}: {:?} back block {:?}",
                    &node,
                    &ptr,
                    &block_hash
                );
                w.write_all(block_hash.as_bytes())?;

                bench.write_children_hashes_ancestor_block_finish(start_time);
            }
        }
        trace!("inner_write_children_hashes end for node {:?}:", &node);

        Ok(())
    }

    /// read a persisted node's hash
    fn inner_read_persisted_node_hash(
        &mut self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieHash, MarfError> {
        if self.unconfirmed_block_id == Some(block_id) {
            // read from unconfirmed trie
            test_debug!(
                "Read persisted node hash from unconfirmed block id {}",
                block_id
            );
            return self.index.get_node_hash_bytes(block_id, ptr);
        }
        let node_hash = match self.blobs.as_mut() {
            Some(blobs) => blobs.get_node_hash_bytes(self.index, block_id, ptr),
            None => self.index.get_node_hash_bytes(block_id, ptr),
        }?;
        Ok(node_hash)
    }

    /// Read a persisted node's hash
    pub fn read_node_hash_bytes(&mut self, ptr: &TriePtr) -> Result<TrieHash, MarfError> {
        if let Some((ref uncommitted_bhh, ref mut trie_ram)) = self.data.uncommitted_writes {
            // special case
            if &self.data.cur_block == uncommitted_bhh {
                return trie_ram.read_node_hash(ptr);
            }
        }

        // some other block or ptr
        match self.data.cur_block_id {
            Some(block_id) => {
                self.bench.read_node_hash_start();
                if let Some(node_hash) = self.cache.load_node_hash(block_id, ptr) {
                    let res = node_hash;
                    self.bench.read_node_hash_finish(true);
                    Ok(res)
                } else {
                    let node_hash = self.inner_read_persisted_node_hash(block_id, ptr)?;
                    self.cache
                        .store_node_hash(block_id, ptr.clone(), node_hash.clone());
                    self.bench.read_node_hash_finish(false);
                    Ok(node_hash)
                }
            }
            None => {
                error!("Not found (no file is open)");
                Err(MarfError::NotFoundError)
            }
        }
    }

    /// Read a persisted node and its hash.
    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), MarfError> {
        self.read_nodetype_maybe_hash(ptr, true)
    }

    /// Read a persisted node
    pub fn read_nodetype_nohash(&mut self, ptr: &TriePtr) -> Result<TrieNodeType, MarfError> {
        self.read_nodetype_maybe_hash(ptr, false)
            .map(|(node, _)| node)
    }

    /// Inner method for reading a node, and optionally its hash as well.
    /// Uses either the DB or the .blobs file, depending on which is configured.
    /// If `read_hash` is `false`, then the returned hash is just the empty hash of all 0's.
    fn inner_read_persisted_nodetype(
        &mut self,
        block_id: u32,
        ptr: &TriePtr,
        read_hash: bool,
    ) -> Result<(TrieNodeType, TrieHash), MarfError> {
        trace!(
            "inner_read_persisted_nodetype({}): {:?} (unconfirmed={:?},{})",
            block_id,
            ptr,
            &self.unconfirmed_block_id,
            self.unconfirmed()
        );
        if self.unconfirmed_block_id == Some(block_id) {
            trace!("Read persisted node from unconfirmed block id {}", block_id);

            // read from unconfirmed trie
            if read_hash {
                return self.index.read_node_type(block_id, &ptr);
            } else {
                return self.index.read_node_type_nohash(block_id, &ptr)
                    .map(|node| (node, TrieHash([0u8; TRIEHASH_ENCODED_SIZE])));
            }
        }
        let (node_inst, node_hash) = match self.blobs.as_mut() {
            Some(blobs) => {
                if read_hash {
                    blobs.read_node_type(self.index, block_id, &ptr)?
                } else {
                    blobs
                        .read_node_type_nohash(self.index, block_id, &ptr)
                        .map(|node| (node, TrieHash([0u8; TRIEHASH_ENCODED_SIZE])))?
                }
            }
            None => {
                if read_hash {
                    self.index.read_node_type(block_id, &ptr)?
                } else {
                    self.index.read_node_type_nohash(block_id, &ptr)
                        .map(|node| (node, TrieHash([0u8; TRIEHASH_ENCODED_SIZE])))?
                }
            }
        };
        Ok((node_inst, node_hash))
    }

    /// Read a node and optionally its hash.  If `read_hash` is false, then an empty hash will be
    /// returned
    /// NOTE: ptr will not be treated as a backptr -- the node returned will be from the
    /// currently-open trie.
    fn read_nodetype_maybe_hash(
        &mut self,
        ptr: &TriePtr,
        read_hash: bool,
    ) -> Result<(TrieNodeType, TrieHash), MarfError> {
        trace!("read_nodetype({:?}): {:?}", &self.data.cur_block, ptr);

        self.data.read_count += 1;
        if Utils::is_backptr(ptr.id()) {
            self.data.read_backptr_count += 1;
        } else if ptr.id() == TrieNodeID::Leaf as u8 {
            self.data.read_leaf_count += 1;
        } else {
            self.data.read_node_count += 1;
        }

        let clear_ptr = ptr.from_backptr();

        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            // special case
            if &self.data.cur_block == uncommitted_bhh {
                return uncommitted_trie.read_nodetype(&clear_ptr);
            }
        }

        // some other block
        match self.data.cur_block_id {
            Some(id) => {
                self.bench.read_nodetype_start();
                let (node_inst, node_hash) = if read_hash {
                    if let Some((node_inst, node_hash)) =
                        self.cache.load_node_and_hash(id, &clear_ptr)
                    {
                        (node_inst, node_hash)
                    } else {
                        let (node_inst, node_hash) =
                            self.inner_read_persisted_nodetype(id, &clear_ptr, read_hash)?;
                        self.cache.store_node_and_hash(
                            id,
                            clear_ptr.clone(),
                            node_inst.clone(),
                            node_hash.clone(),
                        );
                        (node_inst, node_hash)
                    }
                } else {
                    if let Some(node_inst) = self.cache.load_node(id, &clear_ptr) {
                        (node_inst, TrieHash([0u8; TRIEHASH_ENCODED_SIZE]))
                    } else {
                        let (node_inst, _) =
                            self.inner_read_persisted_nodetype(id, &clear_ptr, read_hash)?;
                        self.cache
                            .store_node(id, clear_ptr.clone(), node_inst.clone());
                        (node_inst, TrieHash([0u8; TRIEHASH_ENCODED_SIZE]))
                    }
                };

                self.bench.read_nodetype_finish(false);
                Ok((node_inst, node_hash))
            }
            None => {
                debug!("Not found (no file is open)");
                Err(MarfError::NotFoundError)
            }
        }
    }

    /// Store a node and its hash to the uncommitted state.
    /// If the uncommitted state is not instantiated, then this panics.
    pub fn write_nodetype(
        &mut self,
        disk_ptr: u32,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<(), MarfError> {
        if self.data.readonly {
            return Err(MarfError::ReadOnlyError);
        }

        trace!(
            "write_nodetype({:?}): at {}: {:?} {:?}",
            &self.data.cur_block,
            disk_ptr,
            &hash,
            node
        );

        self.data.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.data.write_leaf_count += 1;
            }
            _ => {
                self.data.write_node_count += 1;
            }
        }

        // Only allow writes when the cur_block is the current in-RAM extending block.
        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            if &self.data.cur_block == uncommitted_bhh {
                return uncommitted_trie.write_nodetype(disk_ptr, node, hash);
            }
        }

        panic!("Tried to write to another Trie besides the currently-buffered one.  This should never happen -- only flush() can write to disk!");
    }

    /// Store a node and its hash to uncommitted state.
    pub fn write_node<N: TrieNode + std::fmt::Debug>(
        &mut self,
        ptr: u32,
        node: &N,
        hash: TrieHash,
    ) -> Result<(), MarfError> {
        if self.data.readonly {
            return Err(MarfError::ReadOnlyError);
        }

        let node_type = node.as_trie_node_type();
        self.write_nodetype(ptr, &node_type, hash)
    }

    /// Get the last slot into which a node will be inserted in the uncommitted state.
    /// Panics if there is no uncommmitted state instantiated.
    pub fn last_ptr(&mut self) -> Result<u32, MarfError> {
        if let Some((_, ref mut uncommitted_trie)) = self.data.uncommitted_writes {
            uncommitted_trie.last_ptr()
        } else {
            panic!("Cannot allocate new ptrs in a Trie that is not in RAM");
        }
    }

    /// Count up the number of trie blocks this storage represents
    pub fn num_blocks(&self) -> usize {
        let result = if self.data.uncommitted_writes.is_some() {
            1
        } else {
            0
        };
        result
            + (self.index.count_blocks()
                .expect("Corruption: SQL Error on a non-fallible query.") as usize)
    }

    pub fn get_benchmarks(&self) -> TrieBenchmark {
        self.bench.clone()
    }

    pub fn bench_mut(&mut self) -> &mut TrieBenchmark {
        self.bench
    }

    pub fn reset_benchmarks(&mut self) {
        self.bench.reset();
    }

    #[cfg(test)]
    pub fn transient_data(&self) -> &TrieStorageTransientData<TTrieId> {
        &self.data
    }

    #[cfg(test)]
    pub fn transient_data_mut(&mut self) -> &mut TrieStorageTransientData<TTrieId> {
        &mut self.data
    }
}