use hmac::Hmac;
use num_bigint::BigUint;
use sha2::Digest;
use sha2::Sha256;

pub(crate) fn compute_u(pk_a: &BigUint, pk_b: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(pk_a.to_bytes_be());
    hasher.update(pk_b.to_bytes_be());
    let hash = hasher.finalize().to_vec();
    BigUint::from_bytes_be(&hash)
}

pub type HmacSha256 = Hmac<Sha256>;

pub fn compute_x(salt: &[u8], password: &[u8]) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password);
    let hash = hasher.finalize().to_vec();
    BigUint::from_bytes_be(&hash)
}
