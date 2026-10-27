#![allow(non_snake_case)]
#![feature(portable_simd)]

pub mod auth;
pub mod blinding;
pub mod client;
pub(crate) mod cpu;
pub mod crt;
pub mod encoding;
pub mod envelope;
pub mod error;
pub mod hqc;
pub mod kdf;
pub mod limits;
pub mod math;
#[cfg(feature = "mceliece-ref")]
pub mod mceliece_ref;
pub mod protocol;
pub mod puzzle;
pub mod replay;
pub mod server;
pub mod session;
pub mod sockets;
pub(crate) mod support;
pub mod traits;

pub use hqc::{Hqc1, Hqc3, Hqc5, HqcScheme, hqc1, hqc3, hqc5};

pub mod stateful;
