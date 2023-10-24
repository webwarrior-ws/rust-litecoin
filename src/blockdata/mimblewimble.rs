// MimbleWimble transaction.
// Only parts that are needed for identifying outputs are implemented.

use crate::prelude::*;
use crate::io;

use consensus::{encode, Decodable};
use secp256k1::PublicKey;
use Script;
use VarInt;

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

fn skip<D: io::Read>(stream: &mut  D, num_bytes: u64) -> () {
    let mut buf= vec![0u8; num_bytes as usize];
    stream.read_exact(&mut buf).unwrap();
}

fn skip_amount<D: io::Read>(stream: &mut D) {
    while (u8::consensus_decode(&mut *stream).expect("read error") & 0x80) != 0 {}
}

fn skip_array<D: io::Read, F>(mut stream: D, read_func: F) where F: FnMut(D) -> () {
    let len = VarInt::consensus_decode(&mut stream)?.0;
    for _ in 0..len {
        read_func(&mut stream);
    }
}

fn skip_input<D: io::Read>(mut stream: D) -> () {
    let features = u8::consensus_decode(&mut stream)?;
    skip(&stream, 32); // output id
    skip(&stream, 33); // commitment
    skip(&stream, 33); // output pub key
    if features & 1 {
    	skip(&stream, 33); // input pub key
    }
    if features & 2 {
    	// extra data
    	skip_array(&stream, | d | skip(d, 1));
    }
    skip(&stream, 64); // signature
}

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        skip(&d,2 * 32);
        return TxBody::consensus_decode(d).map(| body | Transaction{body} );
    }
}

impl Decodable for TxBody {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        return Err(encode::Error::ParseFailed("not yet implemented"));
    }
}

impl Decodable for Output {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        return Err(encode::Error::ParseFailed("not yet implemented"));
    }
}

impl Decodable for OutputMessage {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        return Err(encode::Error::ParseFailed("not yet implemented"));
    }
}

impl Decodable for OutputMessageStandardFields {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        return Err(encode::Error::ParseFailed("not yet implemented"));
    }
}
