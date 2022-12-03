use serde_derive::{Serialize, Deserialize};

// All numeric values of a Trie node when encoded.
// They are all 7-bit numbers -- the 8th bit is used to indicate whether or not the value
// identifies a back-pointer to be followed.
define_u8_enum!(TrieNodeID {
    Empty = 0,
    Leaf = 1,
    Node4 = 2,
    Node16 = 3,
    Node48 = 4,
    Node256 = 5
});