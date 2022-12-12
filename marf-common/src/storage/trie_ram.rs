use std::{io::{Write, Seek, SeekFrom, Read}, collections::VecDeque, ops::Deref};

use sha2::Digest;
use stacks_common::types::chainstate::{TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE};

use crate::{
    tries::{TrieNodeType, TrieNodeID, TrieHashCalculationMode, TriePtr}, 
    MarfTrieId, MarfError, Trie, utils::Utils, TrieHashExtension, BlockMap,
    storage::UncommittedState, 
};

use super::{TrieStorageTransaction, node_hash_reader::NodeHashReader};

/// In-RAM trie storage.
/// Used by TrieFileStorage to buffer the next trie being built.
#[derive(Clone)]
pub struct TrieRAM<T: MarfTrieId> {
    data: Vec<(TrieNodeType, TrieHash)>,
    pub block_header: T,
    readonly: bool,

    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    total_bytes: usize,

    /// does this TrieRAM represent data temporarily moved out of another TrieRAM?
    is_moved: bool,

    parent: T,
}

/// Trie in RAM without the serialization overhead
impl<TTrieId: MarfTrieId> TrieRAM<TTrieId> {
    pub fn new(block_header: &TTrieId, capacity_hint: usize, parent: &TTrieId) -> TrieRAM<TTrieId> {
        TrieRAM {
            data: Vec::with_capacity(capacity_hint),
            block_header: block_header.clone(),
            readonly: false,

            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            total_bytes: 0,

            is_moved: false,

            parent: parent.clone(),
        }
    }

    /// Inner method to instantiate a TrieRAM from existing Trie data.
    fn from_data(block_header: TTrieId, data: Vec<(TrieNodeType, TrieHash)>, parent: TTrieId) -> TrieRAM<TTrieId> {
        TrieRAM {
            data: data,
            block_header: block_header,
            readonly: false,

            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            total_bytes: 0,

            is_moved: false,

            parent: parent,
        }
    }

    /// Instantiate a `TrieRAM` from this `TrieRAM`'s `data` and `block_header`.  This TrieRAM will
    /// have its data set to an empty list.  The new TrieRAM will have its `is_moved` field set to
    /// `true`.
    /// The purpose of this method is to temporarily "re-instate" a `TrieRAM` into a
    /// `TrieFileStorage` while it is being flushed, so that all of the `TrieFileStorage` methods
    /// will continue to work on it.
    ///
    /// Do not call directly; instead, use `with_reinstated_data()`.
    fn move_to(&mut self) -> TrieRAM<TTrieId> {
        let moved_data = std::mem::replace(&mut self.data, vec![]);
        TrieRAM {
            data: moved_data,
            block_header: self.block_header.clone(),
            readonly: self.readonly,

            read_count: self.read_count,
            read_backptr_count: self.read_backptr_count,
            read_node_count: self.read_node_count,
            read_leaf_count: self.read_leaf_count,

            write_count: self.write_count,
            write_node_count: self.write_node_count,
            write_leaf_count: self.write_leaf_count,

            total_bytes: self.total_bytes,

            is_moved: true,

            parent: self.parent.clone(),
        }
    }

    /// Take a given `TrieRAM` and move its `data` to this `TrieRAM`'s data.
    /// The given `TrieRAM` *must* have been created with a prior call to `self.move_to()`.
    ///
    /// Do not call directly; instead use `with_reinstated_data()`.
    fn replace_from(&mut self, other: TrieRAM<TTrieId>) {
        assert!(!self.is_moved);
        assert!(other.is_moved);
        assert_eq!(self.block_header, other.block_header);
        let _ = std::mem::replace(&mut self.data, other.data);
    }

    /// Temporarily re-instate this TrieRAM's data as the `uncommitted_writes` field in a given storage
    /// connection, run the closure `f` with it, and then restore the original `uncommitted_writes` data.
    /// This method does not compose -- calling `with_reinstated_data` within the given closure `f`
    /// will lead to a runtime panic.
    ///
    /// The purpose of this method is to calculate the trie root hash from a trie that is in the
    /// process of being flushed.
    fn with_reinstated_data<F, R>(&mut self, storage: &mut TrieStorageTransaction<TTrieId>, f: F) -> R
    where
        F: FnOnce(&mut TrieRAM<TTrieId>, &mut TrieStorageTransaction<TTrieId>) -> R,
    {
        // do NOT call this function within another instance of this function.  Only tears and
        // misery would result.
        assert!(
            !self.is_moved,
            "FATAL: tried to move a TrieRAM after it had been moved"
        );

        let old_uncommitted_writes = storage.data.uncommitted_writes.take();

        let moved_trie_ram = self.move_to();
        storage.data.uncommitted_writes = Some((
            self.block_header.clone(),
            UncommittedState::RW(moved_trie_ram),
        ));

        let result = f(self, storage);

        // restore
        let (_, moved_extended) = storage
            .data
            .uncommitted_writes
            .take()
            .expect("FATAL: unable to retake moved TrieRAM");

        match moved_extended {
            UncommittedState::RW(trie_ram) => {
                self.replace_from(trie_ram);
            }
            _ => {
                unreachable!()
            }
        };

        storage.data.uncommitted_writes = old_uncommitted_writes;
        result
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn stats(&mut self) -> (u64, u64) {
        let r = self.read_count;
        let w = self.write_count;
        self.read_count = 0;
        self.write_count = 0;
        (r, w)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn node_stats(&mut self) -> (u64, u64, u64) {
        let nr = self.read_node_count;
        let br = self.read_backptr_count;
        let nw = self.write_node_count;

        self.read_node_count = 0;
        self.read_backptr_count = 0;
        self.write_node_count = 0;

        (nr, br, nw)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn leaf_stats(&mut self) -> (u64, u64) {
        let lr = self.read_leaf_count;
        let lw = self.write_leaf_count;

        self.read_leaf_count = 0;
        self.write_leaf_count = 0;

        (lr, lw)
    }

    /// write the trie data to f, using node_data_order to
    ///   iterate over node_data
    pub fn write_trie_indirect<F: Write + Seek>(
        f: &mut F,
        node_data_order: &[u32],
        node_data: &[(TrieNodeType, TrieHash)],
        offsets: &[u32],
        parent_hash: &TTrieId,
    ) -> Result<(), MarfError> {
        assert_eq!(node_data_order.len(), offsets.len());

        // write parent block ptr
        f.seek(SeekFrom::Start(0))?;
        f.write_all(parent_hash.as_bytes())
            .map_err(|e| MarfError::IOError(e))?;
        // write zero-identifier (TODO: this is a convenience hack for now, we should remove the
        //    identifier from the trie data blob)
        f.seek(SeekFrom::Start(BLOCK_HEADER_HASH_ENCODED_SIZE as u64))?;
        f.write_all(&0u32.to_le_bytes())
            .map_err(|e| MarfError::IOError(e))?;

        for (ix, indirect) in node_data_order.iter().enumerate() {
            // dump the node to storage
            Utils::write_nodetype_bytes(
                f,
                &node_data[*indirect as usize].0,
                node_data[*indirect as usize].1,
            )?;

            // next node
            f.seek(SeekFrom::Start(offsets[ix] as u64))?;
        }

        Ok(())
    }

    /// Calculate the MARF root hash from a trie root hash.
    /// This hashes the trie root hash with a geometric series of prior trie hashes.
    fn calculate_marf_root_hash(
        &mut self,
        storage: &mut TrieStorageTransaction<TTrieId>,
        root_hash: &TrieHash,
    ) -> TrieHash {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();

        storage.data.set_block(self.block_header.clone(), None);

        let marf_root_hash = Trie::get_trie_root_hash(storage, root_hash)
            .expect("FATAL: unable to calculate MARF root hash from moved TrieRAM");

        test_debug!("cur_block_hash = {}, cur_block_id = {:?}, self.block_header = {}, have last extended? {}, root_hash: {}, trie_root_hash = {}", &cur_block_hash, &cur_block_id, &self.block_header, storage.data.uncommitted_writes.is_some(), root_hash, &marf_root_hash);

        storage.data.set_block(cur_block_hash, cur_block_id);

        marf_root_hash
    }

    /// Calculate and store the MARF root hash, as well as any necessary intermediate nodes.  Do
    /// this only for deferred hashing mode.
    fn inner_seal_marf(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<TTrieId>,
    ) -> Result<TrieHash, MarfError> {
        // find trie root hash
        debug!("Calculate trie root hash");
        let root_trie_hash = self.calculate_node_hashes(storage_tx, 0)?;

        // find marf root hash -- the hash of the trie root node hash, and the hashes of the
        // geometric series of ancestor tries.  Because the trie is already in the process of
        // being flushed, we have to temporarily reinstate its data into `storage_tx` so we can
        // use it to walk down the various MARF paths needed to query ancestor tries.
        let marf_root_hash = self.with_reinstated_data(storage_tx, |moved_trieram, storage| {
            debug!("Calculate marf root hash");
            moved_trieram.calculate_marf_root_hash(storage, &root_trie_hash)
        });

        if TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode {
            // If we are doing both eager and deferred hashing (i.e. via a test), then verify
            // that we get the same marf hash either way.
            let (_, expected_root_hash) = self.get_nodetype(0)?;
            assert_eq!(expected_root_hash, &marf_root_hash);
        }

        // need to store this hash too, since we deferred calculation
        self.write_node_hash(0, marf_root_hash.clone())?;
        Ok(marf_root_hash)
    }

    /// Get the trie root hash of the trie ram, and update all nodes' root hashes if we're in
    /// deferred hash mode.  Returns the resulting MARF root.  This is part of the seal operation.
    pub fn inner_seal(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<TTrieId>,
    ) -> Result<TrieHash, MarfError> {
        if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
            || TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode
        {
            self.inner_seal_marf(storage_tx)
        } else {
            // already available
            let marf_root_hash =
                self.read_node_hash(&TriePtr::new(TrieNodeID::Node256 as u8, 0, 0))?;
            Ok(marf_root_hash)
        }
    }

    #[cfg(test)]
    pub fn test_inner_seal(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<TTrieId>,
    ) -> Result<TrieHash, MarfError> {
        self.inner_seal(storage_tx)
    }

    /// Seal a trie ram while in the process of dumping it.  If the storage's hash calculation mode
    /// is Deferred, then this updates all the node hashes as well and stores the new node hash.
    /// Otherwise, this is a no-op.
    /// This part of the seal operation.
    pub fn inner_seal_dump(
        &mut self, 
        storage_tx: &mut TrieStorageTransaction<TTrieId>
    ) -> Result<(), MarfError> {
        if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
            || TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode
        {
            let marf_root_hash = self.inner_seal_marf(storage_tx)?;
            debug!("Deferred root hash calculation is {}", &marf_root_hash);
        }
        Ok(())
    }

    /// Recursively calculate all node hashes in this `TrieRAM`.  The top-most call to this method
    /// should pass `0` for `node_ptr`, since this is the pointer to the root node.  Returns the
    /// node hash for the `TrieNode` at `node_ptr`.
    /// If the given `storage_tx`'s hash calculation mode is set to
    /// `TrieHashCalculationMode::Deferred`, then this method will also store each non-leaf node's
    /// hash.
    fn calculate_node_hashes(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<TTrieId>,
        node_ptr: u64,
    ) -> Result<TrieHash, MarfError> {
        let start_time = storage_tx.bench.write_children_hashes_start();
        let mut start_node_time = Some(storage_tx.bench.write_children_hashes_same_block_start());
        let (node, node_hash) = self.get_nodetype(node_ptr as u32)?.to_owned();
        if node.is_leaf() {
            // base case: we already have the hash of the leaf, so return it.
            Ok(node_hash)
        } else {
            // inductive case: calculate children hashes, hash them, and return that hash.
            let mut hasher = crate::TrieHasher::new();
            let empty_node_hash = TrieHash::from_data(&[]);

            node.write_consensus_bytes(storage_tx, &mut hasher)
                .expect("IO Failure pushing to hasher.");

            // count get_nodetype load time for write_children_hashes_same_block benchmark, but
            // only if that code path will be exercised.
            for ptr in node.ptrs().iter() {
                if !Utils::is_backptr(ptr.id()) && ptr.id() != TrieNodeID::Empty as u8 {
                    if let Some(start_node_time) = start_node_time.take() {
                        // count the time taken to load the root node in this case,
                        // but only do so once.
                        storage_tx
                            .bench
                            .write_children_hashes_same_block_finish(start_node_time);
                        break;
                    }
                }
            }

            // calculate the hashes of this node's children, and store them if they're in the
            // same trie.
            for ptr in node.ptrs().iter() {
                if ptr.id() == TrieNodeID::Empty as u8 {
                    // hash of empty string
                    let start_time = storage_tx.bench.write_children_hashes_empty_start();

                    hasher.write_all(empty_node_hash.as_bytes())?;

                    storage_tx
                        .bench
                        .write_children_hashes_empty_finish(start_time);
                } else if !Utils::is_backptr(ptr.id()) {
                    // hash is the hash of this node's children
                    let node_hash = self.calculate_node_hashes(storage_tx, ptr.ptr() as u64)?;

                    // count the time taken to store the hash towards the
                    // write_children_hashes_same_benchmark
                    let start_time = storage_tx.bench.write_children_hashes_same_block_start();
                    trace!(
                        "calculate_node_hashes({:?}): at chr {} ptr {}: {:?} {:?}",
                        &self.block_header,
                        ptr.chr(),
                        ptr.ptr(),
                        &node_hash,
                        node
                    );
                    hasher.write_all(node_hash.as_bytes())?;

                    if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
                        && ptr.id() != TrieNodeID::Leaf as u8
                    {
                        // need to store this hash too, since we deferred calculation
                        self.write_node_hash(ptr.ptr(), node_hash)?;
                    }

                    storage_tx
                        .bench
                        .write_children_hashes_same_block_finish(start_time);
                } else {
                    // hash is that of the block that contains this node
                    let start_time = storage_tx
                        .bench
                        .write_children_hashes_ancestor_block_start();

                    let block_hash = storage_tx.get_block_hash_caching(ptr.back_block())?;
                    trace!(
                        "calculate_node_hashes({:?}): at chr {} bkptr {}: {:?} {:?}",
                        &self.block_header,
                        ptr.chr(),
                        ptr.ptr(),
                        &block_hash,
                        node
                    );
                    hasher.write_all(block_hash.as_bytes())?;

                    storage_tx
                        .bench
                        .write_children_hashes_ancestor_block_finish(start_time);
                }
            }

            // only measure full trie
            if node_ptr == 0 {
                storage_tx
                    .bench
                    .write_children_hashes_finish(start_time, true);
            }

            let node_hash = {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(hasher.finalize().as_slice());
                TrieHash(buf)
            };

            Ok(node_hash)
        }
    }

    /// Walk through the buffered TrieNodes and dump them to f.
    /// This consumes this TrieRAM instance.
    pub fn dump_consume<F: Write + Seek>(mut self, f: &mut F) -> Result<u64, MarfError> {
        // step 1: write out each node in breadth-first order to get their ptr offsets
        let mut frontier: VecDeque<u32> = VecDeque::new();

        let mut node_data = vec![];
        let mut offsets = vec![];

        let start = TriePtr::new(TrieNodeID::Node256 as u8, 0, 0).ptr();
        frontier.push_back(start);

        // first 32 bytes is reserved for the parent block hash
        //    next 4 bytes is the local block identifier
        let mut ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;

        while let Some(pointer) = frontier.pop_front() {
            let (node, _node_hash) = self.get_nodetype(pointer)?;
            // calculate size
            let num_written = Utils::get_node_byte_len(&node);
            ptr += num_written as u64;

            // queue each child
            if !node.is_leaf() {
                let ptrs = node.ptrs();
                let num_children = ptrs.len();
                for i in 0..num_children {
                    if ptrs[i].id != TrieNodeID::Empty as u8 && !Utils::is_backptr(ptrs[i].id) {
                        frontier.push_back(ptrs[i].ptr());
                    }
                }
            }

            node_data.push(pointer);
            offsets.push(ptr as u32);
        }

        assert_eq!(offsets.len(), node_data.len());

        // step 2: update ptrs in all nodes
        let mut i = 0;
        for j in 0..node_data.len() {
            let next_node = &mut self.data[node_data[j] as usize].0;
            if !next_node.is_leaf() {
                let mut ptrs = next_node.ptrs_mut();
                let num_children = ptrs.len();
                for k in 0..num_children {
                    if ptrs[k].id != TrieNodeID::Empty as u8 && !Utils::is_backptr(ptrs[k].id) {
                        ptrs[k].ptr = offsets[i];
                        i += 1;
                    }
                }
            }
        }

        // step 3: write out each node (now that they have the write ptrs)
        TrieRAM::write_trie_indirect(
            f,
            &node_data,
            self.data.as_slice(),
            offsets.as_slice(),
            &self.parent,
        )?;

        Ok(ptr)
    }

    /// load the trie from F.
    /// The trie will have the same structure as the on-disk trie, but it may have nodes in a
    /// different order.
    pub fn load<F: Read + Seek>(f: &mut F, bhh: &TTrieId) -> Result<TrieRAM<TTrieId>, MarfError> {
        let mut data = vec![];
        let mut frontier = VecDeque::new();

        // read parent
        f.seek(SeekFrom::Start(0))?;
        let parent_hash_bytes = Utils::read_hash_bytes(f)?;
        let parent_hash = TTrieId::from_bytes(parent_hash_bytes);

        let root_disk_ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;

        let root_ptr = TriePtr::new(TrieNodeID::Node256 as u8, 0, root_disk_ptr as u32);
        let (mut root_node, root_hash) = Utils::read_nodetype(f, &root_ptr).map_err(|e| {
            error!("Failed to read root node info for {:?}: {:?}", bhh, &e);
            e
        })?;

        let mut next_index = 1;

        if let TrieNodeType::Node256(ref mut data) = root_node {
            // queue children in the same order we stored them
            for ptr in data.ptrs.iter_mut() {
                if ptr.id() != TrieNodeID::Empty as u8 && !Utils::is_backptr(ptr.id()) {
                    frontier.push_back((*ptr).clone());

                    // fix up ptrs
                    ptr.ptr = next_index;
                    next_index += 1;
                }
            }
        } else {
            return Err(MarfError::CorruptionError(
                "First TrieRAM node is not a Node256".to_string(),
            ));
        }

        data.push((root_node, root_hash));

        while frontier.len() > 0 {
            let next_ptr = frontier
                .pop_front()
                .expect("BUG: no ptr in non-empty frontier");
            let (mut next_node, next_hash) = Utils::read_nodetype(f, &next_ptr).map_err(|e| {
                error!("Failed to read node at {:?}: {:?}", &next_ptr, &e);
                e
            })?;

            if !next_node.is_leaf() {
                // queue children in the same order we stored them
                let ptrs: &mut [TriePtr] = match next_node {
                    TrieNodeType::Node4(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node16(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node48(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node256(ref mut data) => &mut data.ptrs,
                    _ => {
                        unreachable!();
                    }
                };

                for ptr in ptrs {
                    if ptr.id() != TrieNodeID::Empty as u8 && !Utils::is_backptr(ptr.id()) {
                        frontier.push_back((*ptr).clone());

                        // fix up ptrs
                        ptr.ptr = next_index;
                        next_index += 1;
                    }
                }
            }

            data.push((next_node, next_hash));
        }

        Ok(TrieRAM::from_data((*bhh).clone(), data, parent_hash))
    }

    /// Hint as to how many entries to allocate for the inner Vec when creating a TrieRAM
    pub fn size_hint(&self) -> usize {
        self.write_count as usize
        // the size hint is used for a capacity guess on the data vec, which is _nodes_
        //  NOT bytes. this led to enormous over-allocations
    }

    /// Clear the TrieRAM contents
    pub fn format(&mut self) -> Result<(), MarfError> {
        if self.readonly {
            trace!("Read-only!");
            return Err(MarfError::ReadOnlyError);
        }

        self.data.clear();
        Ok(())
    }

    /// Read a node's hash from the TrieRAM.  ptr.ptr() is an array index.
    pub fn read_node_hash(&self, ptr: &TriePtr) -> Result<TrieHash, MarfError> {
        let (_, node_trie_hash) = self.data.get(ptr.ptr() as usize).ok_or_else(|| {
            error!(
                "TrieRAM: Failed to read node bytes: {} >= {}",
                ptr.ptr(),
                self.data.len()
            );
            MarfError::NotFoundError
        })?;

        Ok(node_trie_hash.clone())
    }

    /// Get an immutable reference to a node and its hash from the TrieRAM.  ptr.ptr() is an array index.
    pub fn get_nodetype(&self, ptr: u32) -> Result<&(TrieNodeType, TrieHash), MarfError> {
        self.data.get(ptr as usize).ok_or_else(|| {
            error!(
                "TrieRAM get_nodetype({:?}): Failed to read node: {} >= {}",
                &self.block_header,
                ptr,
                self.data.len()
            );
            MarfError::NotFoundError
        })
    }

    /// Get an owned instance of a node and its hash from the TrieRAM.  ptr.ptr() is an array
    /// index.
    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), MarfError> {
        trace!(
            "TrieRAM: read_nodetype({:?}): at {:?}",
            &self.block_header,
            ptr
        );

        self.read_count += 1;
        if Utils::is_backptr(ptr.id()) {
            self.read_backptr_count += 1;
        } else if ptr.id() == TrieNodeID::Leaf as u8 {
            self.read_leaf_count += 1;
        } else {
            self.read_node_count += 1;
        }

        if (ptr.ptr() as u64) >= (self.data.len() as u64) {
            error!(
                "TrieRAM read_nodetype({:?}): Failed to read node {:?}: {} >= {}",
                &self.block_header,
                ptr,
                ptr.ptr(),
                self.data.len()
            );
            Err(MarfError::NotFoundError)
        } else {
            Ok(self.data[ptr.ptr() as usize].clone())
        }
    }

    /// Store a node and its hash to the TrieRAM at the given slot.
    pub fn write_nodetype(
        &mut self,
        node_array_ptr: u32,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<(), MarfError> {
        if self.readonly {
            trace!("Read-only!");
            return Err(MarfError::ReadOnlyError);
        }

        trace!(
            "TrieRAM: write_nodetype({:?}): at {}: {:?} {:?}",
            &self.block_header,
            node_array_ptr,
            &hash,
            node
        );

        self.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.write_leaf_count += 1;
            }
            _ => {
                self.write_node_count += 1;
            }
        }

        if node_array_ptr < (self.data.len() as u32) {
            self.data[node_array_ptr as usize] = (node.clone(), hash);
            Ok(())
        } else if node_array_ptr == (self.data.len() as u32) {
            self.data.push((node.clone(), hash));
            self.total_bytes += Utils::get_node_byte_len(node);
            Ok(())
        } else {
            error!("Failed to write node bytes: off the end of the buffer");
            Err(MarfError::NotFoundError)
        }
    }

    /// Store a node hash into the TrieRAM at a given node slot.
    pub fn write_node_hash(&mut self, node_array_ptr: u32, hash: TrieHash) -> Result<(), MarfError> {
        if self.readonly {
            trace!("Read-only!");
            return Err(MarfError::ReadOnlyError);
        }

        trace!(
            "TrieRAM: write_node_hash({:?}): at {}: {:?}",
            &self.block_header,
            node_array_ptr,
            &hash,
        );

        // can only set the hash of an existing node
        if node_array_ptr < (self.data.len() as u32) {
            self.data[node_array_ptr as usize].1 = hash;
            Ok(())
        } else {
            error!("Failed to write node hash bytes: off the end of the buffer");
            Err(MarfError::NotFoundError)
        }
    }

    /// Get the next ptr value for a node to store.
    pub fn last_ptr(&mut self) -> Result<u32, MarfError> {
        Ok(self.data.len() as u32)
    }

    #[cfg(test)]
    pub fn print_to_stderr(&self) {
        for dat in self.data.iter() {
            eprintln!("{}: {:?}", &dat.1, &dat.0);
        }
    }

    #[cfg(test)]
    pub fn data(&self) -> &Vec<(TrieNodeType, TrieHash)> {
        &self.data
    }
}

impl<T: MarfTrieId> NodeHashReader for TrieRAM<T> {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), MarfError> {
        let (_, node_trie_hash) = self.data.get(ptr.ptr() as usize).ok_or_else(|| {
            error!(
                "TrieRAM: Failed to read node bytes: {} >= {}",
                ptr.ptr(),
                self.data.len()
            );
            MarfError::NotFoundError
        })?;
        w.write_all(node_trie_hash.as_bytes())?;
        Ok(())
    }
}