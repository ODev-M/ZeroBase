//! Wire protocol for the Zerobase daemon.
//!
//! Frames are length-prefixed bincode payloads:
//!
//! ```text
//! +---------------------+--------------------------------+
//! | 4-byte big-endian   | bincode-encoded payload bytes  |
//! | payload length      | (Request or Response)          |
//! +---------------------+--------------------------------+
//! ```
//!
//! `MAX_FRAME_BYTES` caps the size of a single frame so a malicious peer
//! can't make us allocate gigabytes by lying about the length.

#![forbid(unsafe_code)]

mod codec;
mod messages;

pub use codec::{read_frame, write_frame, ProtoError, MAX_FRAME_BYTES};
pub use messages::{
    HandshakeAck, HandshakeHello, KvCmd, KvResult, Request, Response, SqlCmd, SqlResult,
};
