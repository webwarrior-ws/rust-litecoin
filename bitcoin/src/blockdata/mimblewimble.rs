// MimbleWimble transaction.
// Only parts that are needed for identifying outputs are implemented.

use std::io;

use crate::{consensus::{encode, Decodable}, VarInt};
use secp256k1::PublicKey;

pub enum OutputFeatures {
    StandardFieldsFeatureBit = 0x01,
    ExtraDataFeatureBit = 0x02
}

pub struct OutputMessageStandardFields {
    key_exchange_pubkey: PublicKey,
    view_tag: u8,
    masked_value: u64,
    masked_nonce: [u8; 16]
}

pub struct OutputMessage {
    features: OutputFeatures,
    standard_fields: Option<OutputMessageStandardFields>,
    extra_data: Vec<u8>
}

pub struct Output {
    // skip commitment
    // skip sender pub key
    receiver_public_key: PublicKey,
    message: OutputMessage,
    // skip range proof
    // skip signature
}

pub struct TxBody {
    // skip inputs
    outputs: Vec<Output>
    // skip kernels
}

pub struct Transaction {
    // skip: kernel offset, stealth offset
    body: TxBody
}

fn skip<D: io::Read + ?Sized>(stream: &mut D, num_bytes: u64) {
    let mut buf= Vec::<u8>::with_capacity(num_bytes as usize);
    stream.read_exact(&mut buf.as_mut_slice());
}

fn skip_array<D: io::Read + ?Sized, F>(mut stream: &mut D, mut read_func: F) where F: FnMut(&D) {
    let len = VarInt::consensus_decode(&mut stream).unwrap().0;
    for _ in 0..len {
        read_func(stream);
    }
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

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        skip(d,2 * 32);
        return TxBody::consensus_decode(d).map(| body | Transaction{body} );
    }
}

impl Decodable for TxBody {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        return Err(encode::Error::ParseFailed("not yet implemented"));
    }
}

impl Decodable for Output {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        return Err(encode::Error::ParseFailed("not yet implemented"));
    }
}

impl Decodable for OutputMessage {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        return Err(encode::Error::ParseFailed("not yet implemented"));
    }
}

impl Decodable for OutputMessageStandardFields {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        return Err(encode::Error::ParseFailed("not yet implemented"));
    }
}
