use aes::cipher::block_padding::Pkcs7;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, KeyIvInit};

use num_bigint::BigUint;
use num_traits::One;

use sha1::{Digest, Sha1};

use crate::{Aes128CbcDec, Attacker, Error, MessageId, NetworkMessage, NetworkSimulator};

pub struct MIDMattackerGpMin1 {
    received_messages: Vec<Vec<u8>>,
    pub p: BigUint,
}

impl MIDMattackerGpMin1 {
    pub fn new(p: BigUint) -> Self {
        Self {
            received_messages: vec![],
            p,
        }
    }
}

impl Attacker for MIDMattackerGpMin1 {
    fn replace_pk(&mut self, network: &mut NetworkSimulator) -> Result<(), Error> {
        let original_message = self.empty_network(network)?;
        match original_message.message_id {
            MessageId::PubKey => network.send(NetworkMessage {
                sender_id: original_message.sender_id,
                message_id: MessageId::PubKey,
                value: original_message.value.clone(),
            }),
            _ => Err(Error::WrongMessageType),
        }?;
        self.receive_message(original_message.value);
        Ok(())
    }

    fn decode_message(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        // when g = p -1, the pub keys are either 1 or -1
        let pk_a = BigUint::from_bytes_be(&self.received_messages[0]);
        let pk_b = BigUint::from_bytes_be(&self.received_messages[1]);

        let shared_secret = if pk_a == BigUint::one() {
            // if `A` is 1, then `a` must have been even.
            // regardless of whether `B` is -1 or 1, raising it to an even power = 1
            BigUint::one()
        } else {
            // if `A` is -1, then `a` must have been odd. We simply return `B` as the shared secret.
            // if `B` is -1, then -1^odd = -1, and if B = 1, then 1^odd = 1
            pk_b
        };
        let key = shared_secret.to_bytes_be();

        // now compute the hash of 0 Bigint
        let mut hasher = Sha1::new();
        hasher.update(key);
        let aes_key: Vec<u8> = hasher.finalize().to_vec();
        let key = GenericArray::from_slice(&aes_key[..16]);

        let iv: &[u8] = &ciphertext[..16];
        let ct = &ciphertext[16..];

        let mut buf = [0u8; 48];
        let cipher = Aes128CbcDec::new(key, iv.into());
        let pt = cipher
            .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf)
            .unwrap();
        Ok(pt.to_vec())
    }

    fn receive_message(&mut self, msg: Vec<u8>) {
        self.received_messages.push(msg);
    }
}

#[cfg(test)]
mod tests {
    use crate::{Attacker, Participant};

    use super::*;
    use const_decoder::Decoder;
    use num_bigint::BigUint;

    const P_STR: &[u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    const P_BYTES: [u8; 192] = Decoder::Hex.decode(P_STR);

    #[test]
    fn test_midm_attack() {
        let p = BigUint::from_bytes_le(&P_BYTES);
        let g = p.clone() - BigUint::one();

        let mut a = Participant::new(g.clone(), p.clone(), "A".to_string(), "B".to_string());
        let mut b = Participant::new(g, p.clone(), "B".to_string(), "A".to_string());
        let mut e = MIDMattackerGpMin1::new(p);

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

        // now A sends a message to B
        a.send_encrypted_msg(&mut network, "Hello, Bob!".as_bytes().to_vec())
            .unwrap();
        e.relay_message(&mut network).unwrap();
        b.receive_message(&mut network).unwrap();
        assert_eq!(
            *e.received_messages.last().unwrap(),
            "Hello, Bob!".as_bytes().to_vec()
        );

        // and B sends a message to A
        b.send_encrypted_msg(&mut network, "Hi, Alice".as_bytes().to_vec())
            .unwrap();
        e.relay_message(&mut network).unwrap();
        a.receive_message(&mut network).unwrap();
        assert_eq!(
            *e.received_messages.last().unwrap(),
            "Hi, Alice".as_bytes().to_vec()
        );
    }
}
