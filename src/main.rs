use num_bigint::{BigUint, ToBigInt, ToBigUint, RandBigInt};
use hex::FromHex;
use rand::prelude::*;


fn main() {
    let p_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    let decoded = <[u8; 192]>::from_hex(p_str).expect("Decoding failed");

    let p = BigUint::from_bytes_le(&decoded);

    let g = 2.to_biguint().unwrap();

    let mut rng = rand::thread_rng();
    let a = rng.gen_biguint(1000);
    let b = rng.gen_biguint(1000);

    let pub_a = x_mod_p(&g, &a, &p);
    let pub_b = x_mod_p(&g, &b, &p);

    let shared_ab = x_mod_p(&pub_b, &a, &p);
    let shared_ba = x_mod_p(&pub_a, &b, &p);
    assert_eq!(shared_ab, shared_ba);

    println!("{:?}", shared_ab);
    println!("{:?}", shared_ba);
}

fn x_mod_p(g: &BigUint, x: &BigUint, p: &BigUint) -> BigUint {
    let x_mod_p = g.modpow(x, p);
    x_mod_p.clone()
}