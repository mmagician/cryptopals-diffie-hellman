use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, Iv, KeyIvInit};
use aes::Aes128;
use num_bigint::{BigUint, RandBigInt};
use num_traits::identities::Zero;
use rand::prelude::*;
use sha1::{Digest, Sha1};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub struct Attacker {
    received_messages: Vec<Vec<u8>>,
    pub p: BigUint,
}

impl Attacker {
    pub fn replace_pk(&self, network: &mut NetworkSimulator) -> Result<(), Error> {
        let original_message = self.empty_network(network)?;
        match original_message.message_id {
            MessageId::PubKey => network.send(NetworkMessage {
                sender_id: original_message.sender_id,
                message_id: MessageId::PubKey,
                value: self.p.clone().to_bytes_be(),
            }),
            MessageId::Ciphertext => Err(Error::WrongMessageType),
        }
    }

    fn empty_network(&self, network: &mut NetworkSimulator) -> Result<NetworkMessage, Error> {
        let consumed_message = network.consume()?.unwrap();
        Ok(consumed_message)
    }

    pub fn new(p: BigUint) -> Self {
        Self {
            received_messages: vec![],
            p,
        }
    }

    fn decode_message(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        let key: Vec<u8> = BigUint::zero().to_bytes_be();

        // now compute the hash of 0 Bigint
        let mut hasher = Sha1::new();
        hasher.update(key);
        let aes_key: Vec<u8> = hasher.finalize().to_vec();
        let key = GenericArray::from_slice(&aes_key[..16]);

        let iv: &[u8] = &ciphertext[..16];
        let ct = &ciphertext[16..];

        let mut buf = [0u8; 48];
        let cipher = Aes128CbcDec::new(&key, iv.into());
        let pt = cipher
            .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut buf)
            .unwrap();
        Ok(pt.to_vec())
    }

    pub fn relay_message(&mut self, network: &mut NetworkSimulator) -> Result<(), Error> {
        let original_message = self.empty_network(network)?;
        match original_message.message_id {
            MessageId::PubKey => Err(Error::WrongMessageType),
            MessageId::Ciphertext => {
                let decoded_message = self.decode_message(original_message.value.clone())?;
                self.received_messages.push(decoded_message);
                network.send(NetworkMessage {
                    sender_id: original_message.sender_id,
                    message_id: MessageId::Ciphertext,
                    value: original_message.value,
                })
            }
        }
    }
}

pub struct Participant {
    pub id: String,
    pub g: BigUint,
    pub p: BigUint,
    secret: BigUint,
    pub pk: BigUint,
    shared_secret: Option<BigUint>,
    aes_key: Option<Vec<u8>>,
    counterparty_id: String,
    received_messages: Vec<Vec<u8>>,
}

impl Participant {
    pub fn new(g: BigUint, p: BigUint, id: String, counterparty_id: String) -> Self {
        let mut rng = thread_rng();
        let secret = rng.gen_biguint_below(&p);
        let pk = g.modpow(&secret, &p);
        Self {
            g,
            p,
            secret,
            pk,
            id,
            shared_secret: None,
            counterparty_id,
            aes_key: None,
            received_messages: Vec::new(),
        }
    }

    pub fn compute_shared_secret(&self, received_public: BigUint) -> BigUint {
        received_public.modpow(&self.secret, &self.p)
    }

    pub fn share_pk(&self, network: &mut NetworkSimulator) -> Result<(), Error> {
        network.send(NetworkMessage {
            sender_id: self.id.clone(),
            value: self.pk.clone().to_bytes_be(),
            message_id: MessageId::PubKey,
        })
    }

    pub fn receive_message(&mut self, network: &mut NetworkSimulator) -> Result<(), Error> {
        let message = network.consume()?.unwrap();
        if message.sender_id != self.counterparty_id {
            return Err(Error::WrongCounterparty);
        }
        match message.message_id {
            MessageId::PubKey => {
                let v: BigUint = BigUint::from_bytes_be(&message.value);
                self.shared_secret = Some(self.compute_shared_secret(v));
                self.compute_aes_key()?;
            }
            MessageId::Ciphertext => {
                if let Some(aes_key) = &self.aes_key {
                    let key = GenericArray::from_slice(&aes_key[..16]);

                    let iv: &[u8] = message.value[..16].try_into().unwrap();
                    let ct = &message.value[16..];

                    let mut buf = [0u8; 48];
                    let cipher = Aes128CbcDec::new(key, iv.into());
                    let pt = cipher
                        .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut buf)
                        .unwrap();
                    self.received_messages.push(pt.to_vec());
                    println!("Received message: {}", String::from_utf8_lossy(pt));
                } else {
                    return Err(Error::NoAesKey);
                }
            }
        }
        Ok(())
    }

    fn compute_aes_key(&mut self) -> Result<(), Error> {
        // create a Sha1 object
        let mut hasher = Sha1::new();

        if let Some(secret) = &self.shared_secret {
            hasher.update(secret.to_bytes_be());
            self.aes_key = Some(hasher.finalize().to_vec());
        } else {
            return Err(Error::NoSharedSecret);
        }

        Ok(())
    }

    pub fn send_encrypted_msg(
        &self,
        network: &mut NetworkSimulator,
        msg: Vec<u8>,
    ) -> Result<(), Error> {
        if let Some(aes_key) = &self.aes_key {
            let key = GenericArray::from_slice(&aes_key[..16]);
            // generate a random IV of 16 bytes
            let iv = &thread_rng().gen::<[u8; 16]>();

            let truncated_msg: &[u8] = msg.as_slice();
            let mut buf = [0u8; 48];
            let cipher = Aes128CbcEnc::new(key, iv.into());

            let ct = cipher
                .encrypt_padded_b2b_mut::<Pkcs7>(truncated_msg, &mut buf)
                .unwrap();

            // we know that the iv is 16 bytes
            let ct_and_iv = [iv, ct].concat();

            network.send(NetworkMessage {
                sender_id: self.id.clone(),
                value: ct_and_iv.to_vec(),
                message_id: MessageId::Ciphertext,
            })?;
        } else {
            return Err(Error::NoAesKey);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    NetworkFull,
    NetworkEmpty,
    WrongCounterparty,
    NoSharedSecret,
    NoAesKey,
    WrongMessageType,
    DecryptionError,
}

pub struct NetworkSimulator {
    pub message: Option<NetworkMessage>,
}

#[derive(PartialEq)]
pub enum MessageId {
    PubKey,
    Ciphertext,
}

#[derive(PartialEq)]
pub struct NetworkMessage {
    pub sender_id: String,
    pub message_id: MessageId,
    pub value: Vec<u8>,
}

impl NetworkSimulator {
    pub fn new() -> Self {
        Self { message: None }
    }

    pub fn send(&mut self, message: NetworkMessage) -> Result<(), Error> {
        if self.message != None {
            return Err(Error::NetworkFull);
        }
        self.message = Some(message);
        Ok(())
    }

    pub fn consume(&mut self) -> Result<Option<NetworkMessage>, Error> {
        if self.message == None {
            return Err(Error::NetworkEmpty);
        }
        Ok(self.message.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use const_decoder::Decoder;
    use num_bigint::{BigUint, ToBigUint};

    const P_STR: &[u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    const P_BYTES: [u8; 192] = Decoder::Hex.decode(&P_STR);

    #[test]
    fn test_standard_dh() {
        let p = BigUint::from_bytes_le(&P_BYTES);
        let g = 2.to_biguint().unwrap();

        let mut a = Participant::new(g.clone(), p.clone(), "A".to_string(), "B".to_string());
        let mut b = Participant::new(g.clone(), p.clone(), "B".to_string(), "A".to_string());

        let mut network = NetworkSimulator::new();
        // first A sends its public key to B
        a.share_pk(&mut network).unwrap();
        b.receive_message(&mut network).unwrap();
        // then B sends its public key to A
        b.share_pk(&mut network).unwrap();
        a.receive_message(&mut network).unwrap();

        // the shared_secret field is only accessible in unit tests
        let shared_ab = a.shared_secret.clone().unwrap();
        let shared_ba = b.shared_secret.clone().unwrap();

        assert_eq!(shared_ab, shared_ba);

        // now A sends a message to B
        a.send_encrypted_msg(&mut network, "Hello, Bob!".as_bytes().to_vec())
            .unwrap();
        b.receive_message(&mut network).unwrap();
        assert_eq!(b.received_messages.len(), 1);
        assert_eq!(b.received_messages[0], "Hello, Bob!".as_bytes().to_vec());

        // and B sends a message to A
        b.send_encrypted_msg(&mut network, "Hi, Alice".as_bytes().to_vec())
            .unwrap();
        a.receive_message(&mut network).unwrap();
        assert_eq!(a.received_messages.len(), 1);
        assert_eq!(a.received_messages[0], "Hi, Alice".as_bytes().to_vec());
    }

    #[test]
    fn test_midm_attack() {
        let p = BigUint::from_bytes_le(&P_BYTES);
        let g = 2.to_biguint().unwrap();

        let mut a = Participant::new(g.clone(), p.clone(), "A".to_string(), "B".to_string());
        let mut b = Participant::new(g.clone(), p.clone(), "B".to_string(), "A".to_string());
        let mut e = Attacker::new(p.clone());

        let mut network = NetworkSimulator::new();
        // first A sends its public key to B
        a.share_pk(&mut network).unwrap();
        // but Eve intercepts the PK, and instead sends just `p` over to B
        e.replace_pk(&mut network).unwrap();
        b.receive_message(&mut network).unwrap();
        // then B sends its public key to A
        b.share_pk(&mut network).unwrap();
        // but again Eve intercepts
        e.replace_pk(&mut network).unwrap();
        a.receive_message(&mut network).unwrap();

        // the shared_secret field is only accessible in unit tests
        let shared_ab = a.shared_secret.clone().unwrap();
        let shared_ba = b.shared_secret.clone().unwrap();

        // both parties should now have the same shared secret, but unfortunately it's == 0 mod p
        assert_eq!(shared_ab, BigUint::zero());
        assert_eq!(shared_ab, shared_ba);

        // now A sends a message to B
        a.send_encrypted_msg(&mut network, "Hello, Bob!".as_bytes().to_vec())
            .unwrap();
        e.relay_message(&mut network).unwrap();
        b.receive_message(&mut network).unwrap();
        assert_eq!(b.received_messages.len(), 1);
        assert_eq!(b.received_messages[0], "Hello, Bob!".as_bytes().to_vec());
        assert_eq!(e.received_messages[0], "Hello, Bob!".as_bytes().to_vec());

        // and B sends a message to A
        b.send_encrypted_msg(&mut network, "Hi, Alice".as_bytes().to_vec())
            .unwrap();
        e.relay_message(&mut network).unwrap();
        a.receive_message(&mut network).unwrap();
        assert_eq!(a.received_messages.len(), 1);
        assert_eq!(a.received_messages[0], "Hi, Alice".as_bytes().to_vec());
        assert_eq!(e.received_messages[1], "Hi, Alice".as_bytes().to_vec());
    }
}
