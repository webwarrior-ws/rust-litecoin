// MimbleWimble transaction.
// Only parts that are needed for identifying outputs are implemented.
#![allow(missing_docs)]
use crate::prelude::*;
use crate::io;

use consensus::{encode, Decodable};
use secp256k1::{PublicKey, schnorr::Signature};
use Script;
use VarInt;

pub enum OutputFeatures {
    StandardFieldsFeatureBit = 0x01,
    ExtraDataFeatureBit = 0x02
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputMessageStandardFields {
    pub key_exchange_pubkey: PublicKey,
    pub view_tag: u8,
    pub masked_value: u64,
    pub masked_nonce: [u8; 16]
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputMessage {
    pub features: u8,
    pub standard_fields: Option<OutputMessageStandardFields>,
    // skip extra data
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub commitment: [u8; 33],
    pub sender_public_key: PublicKey,
    pub receiver_public_key: PublicKey,
    pub message: OutputMessage,
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub range_proof: [u8; 675],
    pub signature: Signature
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxBody {
    // skip inputs
    pub outputs: Vec<Output>
    // skip kernels
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Transaction {
    // skip: kernel offset, stealth offset
    pub body: TxBody
}

fn skip<D: io::Read>(stream: &mut  D, num_bytes: u64) -> () {
    let mut buf= vec![0u8; num_bytes as usize];
    stream.read_exact(&mut buf).unwrap();
}

fn skip_amount<D: io::Read>(stream: &mut D) {
    while (u8::consensus_decode(&mut *stream).expect("read error") & 0x80) != 0 {}
}

fn read_array_len<D: io::Read>(mut stream: D) -> u64 {
    return VarInt::consensus_decode(&mut stream).expect("read error").0;
}


fn skip_input<D: io::Read>(mut stream: D) -> () {
    let features = u8::consensus_decode(&mut stream).expect("read error");
    skip(&mut stream, 32); // output id
    skip(&mut stream, 33); // commitment
    skip(&mut stream, 33); // output pub key
    if features & 1 != 0 {
    	skip(&mut stream, 33); // input pub key
    }
    if features & 2 != 0 {
    	// extra data
    	let len = read_array_len(&mut stream);
    	skip(&mut stream, len);
    }
    skip(&mut stream, 64); // signature
}

fn skip_kernel<D: io::Read>(mut stream: D) -> () {
    let features = u8::consensus_decode(&mut stream).expect("read error");
    if features & 1 != 0 { // amount
        skip_amount(&mut stream);
    }
    if features & 2 != 0 { // pegin
        skip_amount(&mut stream);
    }
    if features & 4 != 0 { // pegouts
        let len = read_array_len(&mut stream);
        for _ in 0 .. len {
            skip_amount(&mut stream);
            Script::consensus_decode(&mut stream).expect("read error");
        }
    }
    if features & 8 != 0 { // lock height
        skip(&mut stream, 4);
    }
    if features & 16 != 0 { // stealth excess
        skip(&mut stream, 33);
    }
    if features & 32 != 0 { // extra data
        let len = read_array_len(&mut stream);
        skip(&mut stream, len);
    }
    skip(&mut stream, 33); // excess
    skip(&mut stream, 64); // signature
}

impl Decodable for Vec<Output> {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(ret)
    }
}

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        skip(&mut d,2 * 32);
        return TxBody::consensus_decode(d).map(| body | Transaction{body} );
    }
}

impl Decodable for TxBody {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let n_inputs = read_array_len(&mut d);
        for _ in 0..n_inputs {
            skip_input(&mut d);
        }
        let outputs = Vec::<Output>::consensus_decode(&mut d)?;
        let n_kernels = read_array_len(&mut d);
        for _ in 0..n_kernels {
            skip_kernel(&mut d);
        }
        return Ok(TxBody{outputs});
    }
}

impl Decodable for Output {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let commitment = Decodable::consensus_decode(&mut d)?;
        let sender_pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let sender_public_key = PublicKey::from_slice(&sender_pubkey_bytes).unwrap();
        let receiver_pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let receiver_public_key = PublicKey::from_slice(&receiver_pubkey_bytes).unwrap();
        let message = OutputMessage::consensus_decode(&mut d)?;
        let range_proof : [u8;  675] = Decodable::consensus_decode(&mut d)?;
        let signature_bytes: [u8; 64] = Decodable::consensus_decode(&mut d)?;
        let signature =  Signature::from_slice(&signature_bytes).unwrap();
        return Ok(
            Output { 
                commitment, 
                sender_public_key, 
                receiver_public_key, 
                message, 
                range_proof,
                signature 
            }
        );
    }
}

impl Decodable for OutputMessage {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(&mut d)?;
        let standard_fields =
            if features & (OutputFeatures::StandardFieldsFeatureBit as u8) != 0 {
                let pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
                let key_exchange_pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
                let view_tag = u8::consensus_decode(&mut d)?;
                let masked_value = u64::consensus_decode(&mut d)?;
                let masked_nonce: [u8; 16] = Decodable::consensus_decode(&mut d)?;
                Some(
                    OutputMessageStandardFields{
                        key_exchange_pubkey,
                        view_tag,
                        masked_value,
                        masked_nonce})
            } else {
                None
            };
        if features & (OutputFeatures::ExtraDataFeatureBit as u8) != 0 {
            let len = read_array_len(&mut d);
            skip(&mut d, len);
        }
        return Ok(OutputMessage{features, standard_fields});
    }
}
