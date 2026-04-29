//! Length-prefixed frame codec, sync read/write over `Read` / `Write`.

use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Maximum allowed frame payload size, in bytes (8 MiB). A peer that sends
/// a length-prefix above this is considered malicious and the connection
/// is dropped.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error")]
    Encoding,
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
}

impl From<bincode::Error> for ProtoError {
    fn from(_: bincode::Error) -> Self {
        ProtoError::Encoding
    }
}

/// Read one length-prefixed frame and decode it into `T`.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, ProtoError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    let value: T = bincode::deserialize(&payload)?;
    Ok(value)
}

/// Encode `T` and write it as a length-prefixed frame.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<(), ProtoError> {
    let payload = bincode::serialize(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge(payload.len()));
    }
    let len = (payload.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(&payload)?;
    w.flush()?;
    Ok(())
}
