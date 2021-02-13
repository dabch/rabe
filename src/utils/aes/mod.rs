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

use serde::{Serialize, Serializer, ser::SerializeSeq};


#[derive(PartialEq, Eq, Debug)]
pub struct SymmetricCiphertext<'a> {
    nonce: [u8; 13],
    tag: [u8; 16],
    data: &'a mut [u8],
}

impl<'a> Serialize for SymmetricCiphertext<'a> {
    fn serialize<S>(&self, serializer: S)
    -> Result<S::Ok, S::Error>
    where S: Serializer
    {   
        let mut seq = serializer.serialize_seq(None)?;

        // data is deserialized and interpreted as: first nonce, then ciphertext, then tag
        for b in &self.nonce {
            seq.serialize_element(b)?;
        }
        for b in self.data.iter() {
            seq.serialize_element(b)?;
        }
        for b in &self.tag {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}

/// Key Encapsulation Mechanism (Encryption Function)
pub fn encrypt_symmetric<'a, T: core::fmt::Display>(_msg: &T, _plaintext_buf: &'a mut [u8], rng: &mut dyn RngCore) -> Result<SymmetricCiphertext<'a>, RabeError<'static>> {
    let key = kdf(_msg);
    let nonce: [u8; 13] = rng.gen();

    //  key length 256 bit,  tag size 16 byte,  nonce size 13 bytes
    let ccm: ccm::Ccm<Aes256, ccm::consts::U16, ccm::consts::U13> = ccm::Ccm::new(&key);
    let tag = match ccm.encrypt_in_place_detached(&GenericArray::from(nonce), &[], _plaintext_buf) {
        Ok(tag) => tag,
        Err(_) => return Err(RabeError::new("Symmetric Encryption with AES failed")),
    };
    Ok(SymmetricCiphertext{ nonce, tag: tag.into(), data: _plaintext_buf})
}

/// Key Encapsulation Mechanism (Decryption Function)
pub fn decrypt_symmetric<'a, T: core::fmt::Display>(_msg: &T, _ct: SymmetricCiphertext<'a>) -> Result<&'a mut [u8], SymmetricCiphertext<'a>> {
        let key = kdf(_msg);

    let ccm: ccm::Ccm<Aes256, ccm::consts::U16, ccm::consts::U13> = ccm::Ccm::new(&key);
    match ccm.decrypt_in_place_detached(&GenericArray::from(_ct.nonce), &[], _ct.data, &GenericArray::from(_ct.tag)) {
        Ok(()) => Ok(_ct.data),
        Err(_) => return Err(_ct), // decryption failed, return ownership of ciphertext to allow the user to try again if they want
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