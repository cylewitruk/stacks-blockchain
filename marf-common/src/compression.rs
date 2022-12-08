use std::u8;

use lz4_flex::{compress_prepend_size, decompress_size_prepended};

use crate::MarfError;

pub enum CompressionAlgorithm {
    None,
    Lz4,
    Zstd
}

pub trait CompressionProvider {
    fn compress(uncompressed_input: &[u8]) -> Result<CompressionResult, MarfError>;
    fn decompress(compressed_input: &[u8]) -> Result<CompressionResult, MarfError>;
}

pub struct Lz4CompressionProvider {}
pub struct ZstdCompressionProvider {}

pub struct CompressionResult {
    uncompressed_size: usize,
    compressed_size: usize,
    result: Vec<u8>
}

impl CompressionProvider for Lz4CompressionProvider {
    fn compress(uncompressed_input: &[u8]) -> Result<CompressionResult, MarfError> {
        let result = compress_prepend_size(uncompressed_input);

        Ok(CompressionResult { 
            uncompressed_size: uncompressed_input.len(),
            compressed_size: result.len(), 
            result 
        })
    }

    fn decompress(compressed_input: &[u8]) -> Result<CompressionResult, MarfError> {
        let result = decompress_size_prepended(compressed_input)?;
        
        Ok(CompressionResult { 
            compressed_size: compressed_input.len(), 
            uncompressed_size: result.len(),
            result
        })
    }
}

impl From<lz4_flex::block::DecompressError> for MarfError {
    fn from(_: lz4_flex::block::DecompressError) -> Self {
        MarfError::CorruptionError("CORRUPTION: Error decompressing MARF data (LZ4).".to_string())
    }
}

impl From<lz4_flex::block::CompressError> for MarfError {
    fn from(e: lz4_flex::block::CompressError) -> Self {
        MarfError::CorruptionError("CORRUPTION: Error compressing MARF data (LZ4).".to_string())
    }
}