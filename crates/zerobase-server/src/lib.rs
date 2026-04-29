//! `zerobased` library API. The binary (`src/main.rs`) wraps this; tests
//! and embedders can drive [`serve`] directly with a pre-built listener.

#![forbid(unsafe_code)]

pub mod config;
pub mod server;
pub mod session;
pub mod state;

pub use server::run;
pub use state::{DataPlane, ServerState};
