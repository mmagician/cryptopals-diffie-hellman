use num_bigint::{BigUint, RandBigInt};
use rand::prelude::*;

pub struct Participant {
    pub id: String,
    pub g: BigUint,
    pub p: BigUint,
    secret: BigUint,
    pub pk: BigUint,
    pub shared_secret: Option<BigUint>,
    counterparty_id: String,
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
        }
    }

    pub fn compute_shared_secret(&self, received_public: BigUint) -> BigUint {
        received_public.modpow(&self.secret, &self.p)
    }

    pub fn share_message(
        &self,
        network: &mut NetworkSimulator,
        message_id: MessageId,
    ) -> Result<(), Error> {
        match message_id {
            MessageId::PubKey => network.send(NetworkMessage {
                sender_id: self.id.clone(),
                value: self.pk.clone(),
                message_id,
            }),
        }
    }

    pub fn receive_message(&mut self, network: &mut NetworkSimulator) -> Result<(), Error> {
        let message = network.consume()?.unwrap();
        if message.sender_id != self.counterparty_id {
            return Err(Error::WrongCounterparty);
        }
        match message.message_id {
            MessageId::PubKey => {
                self.shared_secret = Some(self.compute_shared_secret(message.value));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    NetworkFull,
    NetworkEmpty,
    WrongCounterparty,
}

pub struct NetworkSimulator {
    pub message: Option<NetworkMessage>,
}

#[derive(PartialEq)]
pub enum MessageId {
    PubKey,
}

#[derive(PartialEq)]
pub struct NetworkMessage {
    pub sender_id: String,
    pub message_id: MessageId,
    pub value: BigUint,
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
        a.share_message(&mut network, MessageId::PubKey).unwrap();
        b.receive_message(&mut network).unwrap();
        // then B sends its public key to A
        b.share_message(&mut network, MessageId::PubKey).unwrap();
        a.receive_message(&mut network).unwrap();

        let shared_ab = a.shared_secret.unwrap();
        let shared_ba = b.shared_secret.unwrap();

        assert_eq!(shared_ab, shared_ba);
    }
}
