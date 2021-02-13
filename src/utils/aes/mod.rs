// use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
// use crypto::digest::Digest;
// use crypto::sha3::Sha3;
// use crypto::{aes, blockmodes, buffer, symmetriccipher};

use core::fmt::{self, Write};

use sha3::{Sha3_256, Digest};
use aes::Aes256;
use ccm::{self, aead::{NewAead, AeadInPlace}};
use ccm::aead::generic_array::GenericArray;

use rand::{RngCore, Rng};
use RabeError;

use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextMetadata {
    nonce: [u8; 13],
    tag: [u8; 16],
}

/// Key Encapsulation Mechanism (Encryption Function)
pub fn encrypt_symmetric<'a, T: core::fmt::Display>(_msg: &T, _plaintext_buf: &'a mut [u8], rng: &mut dyn RngCore) -> Result<CiphertextMetadata, RabeError<'static>> {
    let key = kdf(_msg);
    let nonce: [u8; 13] = rng.gen();

    //  key length 256 bit,  tag size 16 byte,  nonce size 13 bytes
    let ccm: ccm::Ccm<Aes256, ccm::consts::U16, ccm::consts::U13> = ccm::Ccm::new(&key);
    let tag = match ccm.encrypt_in_place_detached(&GenericArray::from(nonce), &[], _plaintext_buf) {
        Ok(tag) => tag,
        Err(_) => return Err(RabeError::new("Symmetric Encryption with AES failed")),
    };
    Ok(CiphertextMetadata{ nonce, tag: tag.into() })
}

/// Key Encapsulation Mechanism (Decryption Function)
pub fn decrypt_symmetric<'a, T: core::fmt::Display>(_msg: &T, _ct_buf: &'a mut [u8], _ct_meta: CiphertextMetadata) -> Result<&'a mut [u8], (&'a mut [u8], CiphertextMetadata)> {
        let key = kdf(_msg);

    let ccm: ccm::Ccm<Aes256, ccm::consts::U16, ccm::consts::U13> = ccm::Ccm::new(&key);
    match ccm.decrypt_in_place_detached(&GenericArray::from(_ct_meta.nonce), &[], _ct_buf, &GenericArray::from(_ct_meta.tag)) {
        Ok(()) => Ok(_ct_buf),
        Err(_) => return Err((_ct_buf, _ct_meta)), // decryption failed, return ownership of ciphertext to allow the user to try again if they want
    }
}

/// This wrapper is needed to manually implement `core::fmt::Write` on the hasher. 
/// It already implements `std::io::Write` which has literally the same effect, but
/// unfortunately is unavailable in a no_std environment.
struct Wrapper<W: Digest>(pub W);

impl<W: Digest> fmt::Write for Wrapper<W> {
    fn write_str(&mut self, arg: &str) -> fmt::Result {
        self.0.update(arg);
        Ok(())
    }
}

/// Key derivation function - turns anything implementing the `Display` trait into a key for AES-256
fn kdf<G: core::fmt::Display>(inp: &G) -> GenericArray<u8, ccm::consts::U32> {
    let mut hasher = Wrapper(Sha3_256::new());
    write!(&mut hasher, "{}", inp).unwrap(); // this LITERALLY can't fail, see the impl of core::fmt::Write for our Wrapper above ;D
    hasher.0.finalize()
}

#[cfg(tests)]
mod tests {
    use super::*;
    #[test]
    fn correctness_test() {
        let key = "7h15 15 4 v3ry 53cr37 k3y";
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        let ciphertext = encrypt_symmetric(&key, &plaintext).unwrap();
        assert_eq!(decrypt_symmetric(&key, &ciphertext).unwrap(), plaintext);
    }
}