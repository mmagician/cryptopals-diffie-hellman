use hex::FromHex;
use num_bigint::{BigUint, RandBigInt, ToBigInt, ToBigUint};
use rand::prelude::*;

pub struct Participant {
    pub g: BigUint,
    pub p: BigUint,
    secret: BigUint,
    pub public: BigUint,
}

impl Participant {
    pub fn new(g: BigUint, p: BigUint) -> Self {
        let mut rng = thread_rng();
        let secret = rng.gen_biguint_below(&p);
        let public = g.modpow(&secret, &p);
        Self {
            g,
            p,
            secret,
            public,
        }
    }

    pub fn get_shared_secret(&self, received_public: BigUint) -> BigUint {
        received_public.modpow(&self.secret, &self.p)
    }
}

fn main() {
    let p_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    let decoded = <[u8; 192]>::from_hex(p_str).expect("Decoding failed");

    let p = BigUint::from_bytes_le(&decoded);

    let g = 2.to_biguint().unwrap();

    let a = Participant::new(g.clone(), p.clone());
    let b = Participant::new(g.clone(), p.clone());

    let shared_ab = a.get_shared_secret(b.public.clone());
    let shared_ba = b.get_shared_secret(a.public.clone());

    assert_eq!(shared_ab, shared_ba);
}
