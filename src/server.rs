use hmac::Mac;
use num_bigint::BigUint;
use num_traits::One;
use rand::{thread_rng, Rng};
use sha2::Digest;
use sha2::Sha256;

use crate::util::compute_u;
use crate::util::compute_x;
use crate::util::HmacSha256;
use crate::Error;
use crate::MessageId;
use crate::NetworkMessage;
use crate::NetworkSimulator;
use crate::Participant;

pub struct Server {
    pub p: BigUint,
    pub g: BigUint,
    pub k: BigUint,
    pub email: Vec<u8>,
    pub password: Vec<u8>,
    salt: Vec<u8>,
    v: BigUint,
    dh: Participant,
    // the result of HMAC-SHA256(K, salt)
    pub expected_response: Option<Vec<u8>>,
}

impl Server {
    pub fn new(p: BigUint, g: BigUint, k: BigUint, email: Vec<u8>, password: Vec<u8>) -> Self {
        let mut rng = thread_rng();
        let salt = rng.gen::<[u8; 16]>().to_vec();
        let x = compute_x(&salt, &password);
        println!("server x: {:?}", x);
        let v = g.modpow(&x, &p);
        Self {
            p: p.clone(),
            g: g.clone(),
            k,
            email,
            password,
            salt,
            v,
            dh: Participant::new(g, p, "server".to_string(), "client".to_string()),
            expected_response: None,
        }
    }

    pub fn issue_challenge(&mut self, network: &mut NetworkSimulator) -> Result<(), Error> {
        // get the messages from the network
        let message_id = network.consume()?.unwrap();
        // first message should be the id = email
        assert!(message_id.message_id == MessageId::Email);
        // verify that the email matches the one we have
        // TODO later we should enable server to hold multiple emails
        assert!(message_id.value == self.email);

        let message_id = network.consume()?.unwrap();
        // second message should be the pub key
        assert!(message_id.message_id == MessageId::PubKey);
        let pk_a = BigUint::from_bytes_be(&message_id.value);

        self.dh.compute_shared_secret(&pk_a);
        let pk_b = (&self.k * &self.v + self.dh.pk.clone()).modpow(&BigUint::one(), &self.p);

        // send the messages over the network (client)
        network.send(NetworkMessage {
            sender_id: self.dh.id.clone(),
            value: self.salt.clone(),
            message_id: MessageId::Salt,
        })?;
        network.send(NetworkMessage {
            sender_id: self.dh.id.clone(),
            value: pk_b.to_bytes_be(),
            message_id: MessageId::PubKey,
        })?;

        let u = compute_u(&pk_a, &pk_b);
        let s_base = &pk_a * &self.v.modpow(&u, &self.p);
        let s = s_base.modpow(&self.dh.secret, &self.p);
        let mut hasher = Sha256::new();
        hasher.update(s.to_bytes_be());
        let kk: Vec<u8> = hasher.finalize().to_vec();

        let mut mac = HmacSha256::new_from_slice(&kk).unwrap();
        mac.update(&self.salt);
        self.expected_response = Some(mac.finalize().into_bytes().to_vec());

        Ok(())
    }

    pub fn validate(&self, network: &mut NetworkSimulator) -> Result<(), Error> {
        // get the messages from the network
        match network.consume() {
            Ok(message) => {
                let message = message.unwrap();
                assert!(message.message_id == MessageId::HMAC);
                match &self.expected_response {
                    Some(expected_hmac) => {
                        if expected_hmac == &message.value {
                            Ok(())
                        } else {
                            Err(Error::ValidationError)
                        }
                    }
                    None => Err(Error::ValidationError),
                }
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod test {
    use const_decoder::Decoder;
    use num_bigint::{BigUint, ToBigUint};

    use crate::{Client, Server};

    const P_STR: &[u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    const P_BYTES: [u8; 192] = Decoder::Hex.decode(P_STR);

    #[test]
    fn test_correct_authentication() {
        let p = BigUint::from_bytes_le(&P_BYTES);
        let g = 2u8.to_biguint().unwrap();

        let mut s = Server::new(
            p.clone(),
            g.clone(),
            BigUint::from(3u8),
            "alice@me.com".to_string().into_bytes(),
            "password123".to_string().into_bytes(),
        );

        let mut c = Client::new(
            p,
            g,
            BigUint::from(3u8),
            "alice@me.com".to_string().into_bytes(),
            "password123".to_string().into_bytes(),
        );

        let mut network = crate::NetworkSimulator::new();
        c.request_login(&mut network).unwrap();

        s.issue_challenge(&mut network).unwrap();

        c.authenticate(&mut network).unwrap();

        s.validate(&mut network).unwrap();
    }
}
