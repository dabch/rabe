//! This is the documentation for the RABE library.
//!
//! * Developped by Georg Bramm, Martin Schanzenbach, Julian Schuette
//! * Type: encryption (attribute-based)
//! * Setting: bilinear groups (asymmetric), based on a modified bn library by zcash
//! * Date: 07/2020
//!
#![allow(dead_code)]
extern crate rabe_bn;
extern crate crypto;
extern crate libc;
extern crate rand;

/// implemented schemes
pub mod schemes;
/// various utilities
pub mod utils;
pub mod ffi;

use std::{fmt::{
    Display,
    Result,
    Formatter
}, error::Error};
use crypto::symmetriccipher::SymmetricCipherError;

#[derive(Debug)]
pub struct RabeError {
    details: String,
}

impl RabeError {
    fn new(msg: &str) -> RabeError {
        RabeError { details: msg.to_string() }
    }
}

impl Display for RabeError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "RabeError: {}", self.details)
    }
}

impl Error for RabeError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl From<SymmetricCipherError> for RabeError {
    fn from(error: SymmetricCipherError) -> Self {
        match error {
            SymmetricCipherError::InvalidPadding => RabeError::new(
                format!("Error during decryption: Invalid Padding!").as_ref()
            ),
            SymmetricCipherError::InvalidLength=> RabeError::new(
                format!("Error during decryption: Invalid Length!").as_ref()
            )
        }
    }
}
