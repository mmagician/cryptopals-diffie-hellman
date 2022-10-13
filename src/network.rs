#[derive(Debug)]
pub enum Error {
    NetworkFull,
    NetworkEmpty,
    WrongCounterparty,
    NoSharedSecret,
    NoAesKey,
    WrongMessageType,
    DecryptionError,
    ValidationError,
}

pub struct NetworkSimulator {
    pub messages: Vec<NetworkMessage>,
}

#[derive(PartialEq, Eq)]
pub enum MessageId {
    PubKey,
    Ciphertext,
    Email,
    Salt,
    HMAC,
}

#[derive(PartialEq, Eq)]
pub struct NetworkMessage {
    pub sender_id: String,
    pub message_id: MessageId,
    pub value: Vec<u8>,
}

impl NetworkSimulator {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    pub fn send(&mut self, message: NetworkMessage) -> Result<(), Error> {
        self.messages.push(message);
        Ok(())
    }

    pub fn consume(&mut self) -> Result<Option<NetworkMessage>, Error> {
        if self.messages.is_empty() {
            return Err(Error::NetworkEmpty);
        }
        Ok(self.messages.pop())
    }
}
