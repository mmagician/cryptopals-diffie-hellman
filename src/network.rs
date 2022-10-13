use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{generic_array::GenericArray};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use num_bigint::{BigUint, RandBigInt};
use num_traits::identities::Zero;
use rand::prelude::*;
use sha1::{Digest, Sha1};

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

#[derive(PartialEq, Eq)]
pub enum MessageId {
    PubKey,
    Ciphertext,
}

#[derive(PartialEq, Eq)]
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
        if self.message.is_some() {
            return Err(Error::NetworkFull);
        }
        self.message = Some(message);
        Ok(())
    }

    pub fn consume(&mut self) -> Result<Option<NetworkMessage>, Error> {
        if self.message.is_none() {
            return Err(Error::NetworkEmpty);
        }
        Ok(self.message.take())
    }
}