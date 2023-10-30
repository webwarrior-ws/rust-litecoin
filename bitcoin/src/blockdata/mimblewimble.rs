// MimbleWimble transaction.
// Only parts that are needed for identifying outputs are implemented.
#![allow(missing_docs)]
use std::io;

use crate::{consensus::{encode, Decodable}, VarInt};
use secp256k1::PublicKey;
use crate::blockdata::script::ScriptBuf;

pub enum OutputFeatures {
    StandardFieldsFeatureBit = 0x01,
    ExtraDataFeatureBit = 0x02
}

#[derive(Debug)]
pub struct OutputMessageStandardFields {
    pub key_exchange_pubkey: PublicKey,
    pub view_tag: u8,
    pub masked_value: u64,
    pub masked_nonce: [u8; 16]
}

#[derive(Debug)]
pub struct OutputMessage {
    pub features: u8,
    pub standard_fields: Option<OutputMessageStandardFields>,
    // skip extra data
}

#[derive(Debug)]
pub struct Output {
    // skip commitment
    // skip sender pub key
    pub receiver_public_key: PublicKey,
    pub message: OutputMessage,
    // skip range proof
    // skip signature
}

#[derive(Debug)]
pub struct TxBody {
    // skip inputs
    pub outputs: Vec<Output>
    // skip kernels
}

#[derive(Debug)]
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

fn skip_input<D: io::Read + ?Sized>(stream: &mut D) {
    let features = u8::consensus_decode(stream).unwrap();
    skip(stream, 32); // output id
    skip(stream, 33); // commitment
    skip(stream, 33); // output pub key
    if features & 1 != 0 {
    	skip(stream, 33); // input pub key
    }
    if features & 2 != 0 {
    	// extra data
        let len = VarInt::consensus_decode(stream).unwrap().0;
        skip(stream, len);
    }
    skip(stream, 64); // signature
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

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        skip(d,2 * 32);
        return TxBody::consensus_decode(d).map(| body | Transaction{body} );
    }
}

impl Decodable for TxBody {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let n_inputs = read_array_len(d);
        for _ in 0..n_inputs {
            skip_input(d);
        }
        let outputs = Vec::<Output>::consensus_decode(d)?;
        let n_kernels = read_array_len(d);
        for _ in 0..n_kernels {
            skip_kernel(d);
        }
        return Ok(TxBody{outputs});
    }
}

impl Decodable for Output {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        skip(d, 33); // commitment
        skip(d, 33); // sender pub key
        let pubkey_bytes : [u8; 33] = Decodable::consensus_decode(d)?;
        let receiver_public_key = PublicKey::from_slice(&pubkey_bytes).unwrap();
        let message = OutputMessage::consensus_decode(d)?;
        skip(d, 675); // range proof
        skip(d, 64); // signature
        return Ok(Output { receiver_public_key, message });
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
        if features & (OutputFeatures::ExtraDataFeatureBit as u8) != 0 {
            let len = read_array_len(d);
            skip(d, len);
        }
        return Ok(OutputMessage{features, standard_fields});
    }
}
