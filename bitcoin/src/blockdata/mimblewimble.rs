// MimbleWimble transaction.
// Only parts that are needed for identifying outputs are implemented.
#![allow(missing_docs)]

use crate::prelude::*;
use crate::io;

use crate::consensus::{encode, Decodable, Encodable};
use secp256k1::PublicKey;
use crate::blockdata::script::ScriptBuf;
use crate::VarInt;

pub enum OutputFeatures {
    StandardFieldsFeatureBit = 0x01,
    ExtraDataFeatureBit = 0x02
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct OutputMessageStandardFields {
    pub key_exchange_pubkey: PublicKey,
    pub view_tag: u8,
    pub masked_value: u64,
    pub masked_nonce: [u8; 16]
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct OutputMessage {
    pub features: u8,
    pub standard_fields: Option<OutputMessageStandardFields>,
    pub extra_data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Output {
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub commitment: [u8; 33],
    pub sender_public_key: PublicKey,
    pub receiver_public_key: PublicKey,
    pub message: OutputMessage,
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub range_proof: [u8; 675],
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: [u8; 64],
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Input {
    // skip features
    pub output_id: [u8; 32],
    // skip commitment
    // skip input_public_key
    // skip output_public_pey
    // skip extra_data
    // skip signature
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct TxBody {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    // skip kernels
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Transaction {
    // skip: kernel offset, stealth offset
    pub body: TxBody
}

fn skip<D: io::Read + ?Sized>(stream: &mut D, num_bytes: u64) {
    let mut buf= Vec::<u8>::with_capacity(num_bytes as usize);
    let _ = stream.read_exact(&mut buf.as_mut_slice());
}

fn skip_amount<D: io::Read + ?Sized>(stream: &mut D) {
    for _ in 0..10 {
        if (u8::consensus_decode(stream).expect("read error") & 0x80) == 0 {
            break;
        }
    }
}

fn read_array_len<D: io::Read + ?Sized>(stream: &mut D) -> u64 {
    return VarInt::consensus_decode(stream).expect("read error").0;
}

fn skip_kernel<D: io::Read + ?Sized>(stream: &mut D) {
    let features = u8::consensus_decode(stream).expect("read error");
    if features & 1 != 0 { // amount
        skip_amount(stream);
    }
    if features & 2 != 0 { // pegin
        skip_amount(stream);
    }
    if features & 4 != 0 { // pegout
        skip_amount(stream);
        let _: ScriptBuf = Decodable::consensus_decode(stream).expect("read error");
    }
    if features & 8 != 0 { // lock height
        skip(stream, 4);
    }
    if features & 16 != 0 { // stealth excess
        skip(stream, 33);
    }
    if features & 32 != 0 { // extra data
        let len = read_array_len(stream);
        skip(stream, len);
    }
    skip(stream, 33); // excess
    skip(stream, 64); // signature
}

impl Decodable for Vec<Input> {
    fn consensus_decode<D: io::Read + ?Sized>(stream: &mut D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(stream)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(stream)?);
        }
        Ok(ret)
    }
}

impl Decodable for Input {
    fn consensus_decode<D: io::Read + ?Sized>(stream: &mut D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(stream)?;
        let output_id: [u8; 32] = Decodable::consensus_decode(stream)?;
        skip(stream, 33); // commitment
        skip(stream, 33); // output pub key
        if features & 1 != 0 {
            skip(stream, 33); // input pub key
        }
        if features & 2 != 0 {
            // extra data
            let len = read_array_len(stream);
            skip(stream, len);
        }
        skip(stream, 64); // signature
        return Ok(Input { output_id });
    }
}

impl Decodable for Vec<Output> {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(d)?);
        }
        Ok(ret)
    }
}

impl Encodable for Vec<Output> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.len() as u64).consensus_encode(writer)?;
        for output in self {
            len += output.consensus_encode(writer)?;
        }
        return Ok(len);
    }
}

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        skip(d,2 * 32);
        return TxBody::consensus_decode(d).map(| body | Transaction{body} );
    }
}

impl Decodable for TxBody {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let inputs = Vec::<Input>::consensus_decode(d)?;
        let outputs = Vec::<Output>::consensus_decode(d)?;
        let n_kernels = read_array_len(d);
        for _ in 0..n_kernels {
            skip_kernel(d);
        }
        return Ok(TxBody{ inputs, outputs });
    }
}

impl Encodable for Output {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.commitment.consensus_encode(writer)?;
        len += self.sender_public_key.serialize().consensus_encode(writer)?;
        len += self.receiver_public_key.serialize().consensus_encode(writer)?;
        len += self.message.consensus_encode(writer)?;
        len += self.range_proof.consensus_encode(writer)?;
        len += self.signature.consensus_encode(writer)?;
        return Ok(len);
    }
}

impl Decodable for Output {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let commitment = Decodable::consensus_decode(d)?;
        let sender_pubkey_bytes : [u8; 33] = Decodable::consensus_decode(d)?;
        let sender_public_key = PublicKey::from_slice(&sender_pubkey_bytes).unwrap();
        let receiver_pubkey_bytes : [u8; 33] = Decodable::consensus_decode(d)?;
        let receiver_public_key = PublicKey::from_slice(&receiver_pubkey_bytes).unwrap();
        let message = OutputMessage::consensus_decode(d)?;
        let range_proof : [u8;  675] = Decodable::consensus_decode(d)?;
        let signature: [u8; 64] = Decodable::consensus_decode(d)?;
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
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(d)?;
        let standard_fields =
            if features & (OutputFeatures::StandardFieldsFeatureBit as u8) != 0 {
                let pubkey_bytes : [u8; 33] = Decodable::consensus_decode(d)?;
                let key_exchange_pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
                let view_tag = u8::consensus_decode(d)?;
                let masked_value = u64::consensus_decode(d)?;
                let masked_nonce: [u8; 16] = Decodable::consensus_decode(d)?;
                Some(
                    OutputMessageStandardFields{
                        key_exchange_pubkey,
                        view_tag,
                        masked_value,
                        masked_nonce})
            } else {
                None
            };
        let extra_data: Vec<u8> =
            if features & (OutputFeatures::ExtraDataFeatureBit as u8) != 0 {
                Decodable::consensus_decode(d)?
            }
            else {
                vec! []
            };
        return Ok(OutputMessage{features, standard_fields, extra_data});
    }
}

impl Encodable for OutputMessage {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(writer)?;
        match self.standard_fields {
            Some(ref fields) => {
                len += fields.key_exchange_pubkey.serialize().consensus_encode(writer)?;
                len += fields.view_tag.consensus_encode(writer)?;
                len += fields.masked_value.consensus_encode(writer)?;
                len += fields.masked_nonce.consensus_encode(writer)?;
            }
            None => {}
        }
        if self.features & (OutputFeatures::ExtraDataFeatureBit as u8) != 0 {
            len += self.extra_data.consensus_encode(writer)?;
        }
        return Ok(len);
    }
}
