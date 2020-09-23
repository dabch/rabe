use rabe_bn::{G1, G2, Fr};
use crypto::{
    blake2b::Blake2b,
    digest::Digest
};

/// hash a String to an element of G1 using blake2b and generator g
pub fn blake2b_hash_g1(g: G1, data: &String) -> G1 {
    return g * blake2b_hash(data)
}

/// hash a String to an element of G2 using blake2b and generator g
pub fn blake2b_hash_g2(g: G2, data: &String) -> G2 {
    return g * blake2b_hash(data)
}

/// hash a String to Fr using blake2b
pub fn blake2b_hash(data: &String) -> Fr {
    let mut result:[u8; 64] = [0; 64];
    let mut b2b = Blake2b::new(64);
    b2b.input(data.as_bytes());
    b2b.result(&mut result);
    return Fr::interpret(&result)
}