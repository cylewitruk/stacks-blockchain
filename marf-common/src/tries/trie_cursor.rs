use stacks_common::util::hash::to_hex;

use crate::{CursorError, utils::Utils, MarfTrieId};

use super::{TriePath, nodes::TrieNodeType, TriePtr};

/// Cursor structure for walking down one or more Tries.  This structure helps other parts of the
/// codebase remember which nodes were visited, which blocks they came from, and which pointers
/// were walked.  In particular, it's useful for figuring out where to insert a new node, and which
/// nodes to visit when updating the root node hash.
#[derive(Debug, Clone, PartialEq)]
pub struct TrieCursor<T: MarfTrieId> {
    pub path: TriePath,                  // the path to walk
    pub index: usize,                    // index into the path
    pub node_path_index: usize,          // index into the currently-visited node's compressed path
    pub nodes: Vec<TrieNodeType>,        // list of nodes this cursor visits
    pub node_ptrs: Vec<TriePtr>,         // list of ptr branches this cursor has taken
    pub block_hashes: Vec<T>, // list of Tries we've visited.  block_hashes[i] corresponds to node_ptrs[i]
    pub last_error: Option<CursorError>, // last error encountered while walking (used to make sure the client calls the right "recovery" method)
}

impl<T: MarfTrieId> TrieCursor<T> {
    pub fn new(path: &TriePath, root_ptr: TriePtr) -> TrieCursor<T> {
        TrieCursor {
            path: path.clone(),
            index: 0,
            node_path_index: 0,
            nodes: vec![],
            node_ptrs: vec![root_ptr],
            block_hashes: vec![],
            last_error: None,
        }
    }

    /// what point in the path are we at now?
    /// Will be None only if we haven't taken a step yet.
    pub fn chr(&self) -> Option<u8> {
        if self.index > 0 && self.index <= self.path.len() {
            Some(self.path.as_bytes()[self.index - 1])
        } else {
            None
        }
    }

    /// what offset in the path are we at?
    pub fn tell(&self) -> usize {
        self.index
    }

    /// what is the offset in the node's compressed path?
    pub fn ntell(&self) -> usize {
        self.node_path_index
    }

    /// Are we a the [E]nd [O]f [P]ath?
    pub fn eop(&self) -> bool {
        self.index == self.path.len()
    }

    /// last ptr visited
    pub fn ptr(&self) -> TriePtr {
        // should always be true by construction
        assert!(self.node_ptrs.len() > 0);
        self.node_ptrs[self.node_ptrs.len() - 1].clone()
    }

    /// last node visited.
    /// Will only be None if we haven't taken a step yet.
    pub fn node(&self) -> Option<TrieNodeType> {
        match self.nodes.len() {
            0 => None,
            _ => Some(self.nodes[self.nodes.len() - 1].clone()),
        }
    }

    /// Are we at the [E]nd [O]f a [N]ode's [P]ath?
    pub fn eonp(&self, node: &TrieNodeType) -> bool {
        match node {
            TrieNodeType::Leaf(ref data) => self.node_path_index == data.path.len(),
            TrieNodeType::Node4(ref data) => self.node_path_index == data.path.len(),
            TrieNodeType::Node16(ref data) => self.node_path_index == data.path.len(),
            TrieNodeType::Node48(ref data) => self.node_path_index == data.path.len(),
            TrieNodeType::Node256(ref data) => self.node_path_index == data.path.len(),
        }
    }

    /// Walk to the next node, following its compressed path as far as we can and then walking to
    /// its child pointer.  If we successfully follow the path, then return the pointer we reached.
    /// Otherwise, if we reach the end of the path, return None.  If the path diverges or a node
    /// cannot be found, then return an Err.
    ///
    /// This method does not follow back-pointers, and will return Err if a back-pointer is
    /// reached.  The caller will need to manually call walk() on the last node visited to get the
    /// back-pointer, shunt to the node it points to, and then call walk_backptr_step_backptr() to
    /// record the back-pointer that was followed.  Once the back-pointer has been followed,
    /// caller should call walk_backptr_step_finish().  This is specifically relevant to the MARF,
    /// not to the individual tries.
    pub fn walk(
        &mut self,
        node: &TrieNodeType,
        block_hash: &T,
    ) -> Result<Option<TriePtr>, CursorError> {
        // can only be called if we called the appropriate "repair" method or if there is no error
        assert!(self.last_error.is_none());

        trace!("cursor: walk: node = {:?} block = {:?}", node, block_hash);

        // walk this node
        self.nodes.push((*node).clone());
        self.node_path_index = 0;

        if self.index >= self.path.len() {
            trace!("cursor: out of path");
            return Ok(None);
        }

        let node_path = node.path_bytes();
        let path_bytes = self.path.as_bytes();

        // consume as much of the compressed path as we can
        for i in 0..node_path.len() {
            if node_path[i] != path_bytes[self.index] {
                // diverged
                trace!("cursor: diverged({} != {}): i = {}, self.index = {}, self.node_path_index = {}", to_hex(&node_path), to_hex(path_bytes), i, self.index, self.node_path_index);
                self.last_error = Some(CursorError::PathDiverged);
                return Err(CursorError::PathDiverged);
            }
            self.index += 1;
            self.node_path_index += 1;
        }

        // walked to end of the node's compressed path.
        // Find the pointer to the next node.
        if self.index < self.path.len() {
            let chr = path_bytes[self.index];
            self.index += 1;
            let mut ptr_opt = node.walk(chr);

            let do_walk = match ptr_opt {
                Some(ptr) => {
                    if !Utils::is_backptr(ptr.id()) {
                        // not going to follow a back-pointer
                        self.node_ptrs.push(ptr);
                        self.block_hashes.push(block_hash.clone());
                        true
                    } else {
                        // the caller will need to follow the backptr, and call
                        // repair_backptr_step_backptr() for each node visited, and then repair_backptr_finish()
                        // once the final ptr and block_hash are discovered.
                        self.last_error = Some(CursorError::BackptrEncountered(ptr));
                        false
                    }
                }
                None => {
                    self.last_error = Some(CursorError::ChrNotFound);
                    false
                }
            };

            if !do_walk {
                ptr_opt = None;
            }

            if ptr_opt.is_none() {
                assert!(self.last_error.is_some());

                trace!(
                    "cursor: not found: chr = 0x{:02x}, self.index = {}, self.path = {:?}",
                    chr,
                    self.index - 1,
                    &path_bytes
                );
                return Err(self.last_error.clone().unwrap());
            } else {
                return Ok(ptr_opt);
            }
        } else {
            trace!("cursor: now out of path");
            return Ok(None);
        }
    }

    /// Replace the last-visited node and ptr within this trie.  Used when doing a copy-on-write or
    /// promoting a node, so the cursor state accurately reflects the nodes and tries visited.
    #[inline]
    pub fn repair_retarget(&mut self, node: &TrieNodeType, ptr: &TriePtr, hash: &T) -> () {
        // this can only be called if we failed to walk to a node (this method _should not_ be
        // called if we walked to a backptr).
        if Some(CursorError::ChrNotFound) != self.last_error
            && Some(CursorError::PathDiverged) != self.last_error
        {
            eprintln!("{:?}", &self.last_error);
            panic!();
        }

        self.nodes.pop();
        self.node_ptrs.pop();
        self.block_hashes.pop();

        self.nodes.push(node.clone());
        self.node_ptrs.push(ptr.clone());
        self.block_hashes.push(hash.clone());

        self.last_error = None;
    }

    /// Record that a node was walked to by way of a back-pointer.
    /// next_node should be the node walked to.
    /// ptr is the ptr we'll be walking from, off of next_node.
    /// block_hash is the block where next_node came from.
    #[inline]
    pub fn repair_backptr_step_backptr(
        &mut self,
        next_node: &TrieNodeType,
        ptr: &TriePtr,
        block_hash: T,
    ) -> () {
        // this can only be called if we walked to a backptr.
        // If it's anything else, we're in trouble.
        if Some(CursorError::ChrNotFound) == self.last_error
            || Some(CursorError::PathDiverged) == self.last_error
        {
            eprintln!("{:?}", &self.last_error);
            panic!();
        }

        trace!(
            "Cursor: repair_backptr_step_backptr ptr={:?} block_hash={:?} next_node={:?}",
            ptr,
            &block_hash,
            next_node
        );

        let backptr = TriePtr::new(Utils::set_backptr(ptr.id()), ptr.chr(), ptr.ptr()); // set_backptr() informs update_root_hash() to skip this node
        self.node_ptrs.push(backptr);
        self.block_hashes.push(block_hash);

        self.nodes.push(next_node.clone());
    }

    /// Record that we landed on a non-backptr from a backptr.
    /// ptr is a non-backptr that refers to the node we landed on.
    #[inline]
    pub fn repair_backptr_finish(&mut self, ptr: &TriePtr, block_hash: T) -> () {
        // this can only be called if we walked to a backptr.
        // If it's anything else, we're in trouble.
        if Some(CursorError::ChrNotFound) == self.last_error
            || Some(CursorError::PathDiverged) == self.last_error
        {
            eprintln!("{:?}", &self.last_error);
            panic!();
        }
        assert!(!Utils::is_backptr(ptr.id()));

        trace!(
            "Cursor: repair_backptr_finish ptr={:?} block_hash={:?}",
            &ptr,
            &block_hash
        );

        self.node_ptrs.push(ptr.clone());
        self.block_hashes.push(block_hash);

        self.last_error = None;
    }
}