use crate::{Error, MessageId, NetworkMessage, NetworkSimulator};

pub trait Attacker {
    fn replace_pk(&mut self, network: &mut NetworkSimulator) -> Result<(), Error>;

    fn empty_network(&self, network: &mut NetworkSimulator) -> Result<NetworkMessage, Error> {
        let consumed_message = network.consume()?.unwrap();
        Ok(consumed_message)
    }

    fn decode_message(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error>;

    fn relay_message(&mut self, network: &mut NetworkSimulator) -> Result<(), Error> {
        let original_message = self.empty_network(network)?;
        match original_message.message_id {
            MessageId::PubKey => Err(Error::WrongMessageType),
            MessageId::Ciphertext => {
                let decoded_message = self.decode_message(original_message.value.clone())?;
                self.receive_message(decoded_message);
                network.send(NetworkMessage {
                    sender_id: original_message.sender_id,
                    message_id: MessageId::Ciphertext,
                    value: original_message.value,
                })
            }
        }
    }

    fn receive_message(&mut self, msg: Vec<u8>);
}

pub mod midm;
pub mod midm_g1;
pub mod midm_gp;
pub mod midm_gp_min1;
