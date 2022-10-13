use hmac::Mac;
use num_bigint::BigInt;
use num_bigint::BigUint;

use num_bigint::ToBigInt;
use num_traits::One;
use sha2::Digest;
use sha2::Sha256;

use crate::util::HmacSha256;
use crate::{
    util::{compute_u, compute_x},
    Error, MessageId, NetworkMessage, NetworkSimulator, Participant,
};

pub struct Client {
    pub p: BigUint,
    pub g: BigUint,
    pub k: BigUint,
    pub email: Vec<u8>,
    pub password: Vec<u8>,
    pub dh: Participant,
}

impl Client {
    pub fn new(p: BigUint, g: BigUint, k: BigUint, email: Vec<u8>, password: Vec<u8>) -> Self {
        Self {
            p: p.clone(),
            g: g.clone(),
            k,
            email,
            password,
            dh: Participant::new(g, p, "client".to_string(), "server".to_string()),
        }
    }

    pub fn request_login(&mut self, network: &mut NetworkSimulator) -> Result<(), Error> {
        self.dh.share_pk(network)?;

        let id_message = NetworkMessage {
            sender_id: self.dh.id.clone(),
            value: self.email.clone(),
            message_id: MessageId::Email,
        };
        network.send(id_message)?;

        Ok(())
    }

    pub fn authenticate(&mut self, network: &mut NetworkSimulator) -> Result<(), Error> {
        let message = network.consume()?.unwrap();
        assert!(message.message_id == MessageId::PubKey);
        let pk_b = BigUint::from_bytes_be(&message.value);

        let message = network.consume()?.unwrap();
        assert!(message.message_id == MessageId::Salt);
        let salt = message.value;

        let u = compute_u(&self.dh.pk, &pk_b);

        let x = compute_x(&salt, &self.password);

        // some manipulation needed in order to not underflow
        let s_base = pk_b.to_bigint().unwrap()
            - &(&self.k * &self.g.modpow(&x, &self.p)).to_bigint().unwrap();
        let s_base = s_base
            .modpow(&BigInt::one(), &self.p.to_bigint().unwrap())
            .to_biguint()
            .unwrap();
        let exp = (&self.dh.secret + &u * &x).modpow(&BigUint::one(), &self.p);
        let s = s_base.modpow(&exp, &self.p);

        let mut hasher = Sha256::new();
        hasher.update(s.to_bytes_be());
        let kk: Vec<u8> = hasher.finalize().to_vec();

        let mut mac = HmacSha256::new_from_slice(&kk).unwrap();
        mac.update(&salt);

        let hmac = mac.finalize().into_bytes().to_vec();
        let hmac_message = NetworkMessage {
            sender_id: self.dh.id.clone(),
            value: hmac,
            message_id: MessageId::HMAC,
        };
        network.send(hmac_message)?;

        Ok(())
    }
}
