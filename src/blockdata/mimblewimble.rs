// MimbleWimble transaction.
// Only parts that are needed for identifying outputs are implemented.


use io;

use consensus::{encode, Decodable};
use impl_vec;
use secp256k1::PublicKey;
use Script;
use VarInt;

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

pub struct Transaction {
    // skip: kernel offset, stealth offset
    pub body: TxBody
}

fn skip<D: io::Read>(stream: D, num_bytes: u64) -> () {
    io::copy(&mut stream.take(num_bytes), &mut io::sink()).expect("read error");
}

fn skip_amount<D: io::Read>(stream: D) {
    for _ in 0..10 {
        if (u8::consensus_decode(&mut stream).expect("read error") & 0x80) == 0 {
            break;
        }
    }
}

fn skip_array<D: io::Read, F>(mut stream: D, read_func: F) where F: FnMut(D) -> () {
    let len = VarInt::consensus_decode(&mut stream).expect("read error").0;
    for _ in 0..len {
        read_func(stream);
    }
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
    	skip_array(&mut stream, | d | skip(d, 1));
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
    if features & 4 != 0 { // pegout
        skip_amount(&mut stream);
        Script::consensus_decode(&mut stream).expect("read error");
    }
    if features & 8 != 0 { // lock height
        skip(&mut stream, 4);
    }
    if features & 16 != 0 { // stealth excess
        skip(&mut stream, 33);
    }
    if features & 32 != 0 { // extra data
        skip_array(&mut stream, | d | skip(d, 1));
    }
    skip(&mut stream, 33); // excess
    skip(&mut stream, 64); // signature
}

impl_vec!(Output);

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        skip(&mut d,2 * 32);
        return TxBody::consensus_decode(d).map(| body | Transaction{body} );
    }
}

impl Decodable for TxBody {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        skip_array(&mut d, skip_input);
        let outputs = Vec::<Output>::consensus_decode(d)?;
        skip_array(&mut d, skip_kernel);
        return Ok(TxBody{outputs});
    }
}

impl Decodable for Output {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        skip(&mut d, 33); // commitment
        skip(&mut d, 33); // sender pub key
        let pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let receiver_public_key = PublicKey::from_slice(&pubkey_bytes)?;
        let message = OutputMessage::consensus_decode(&mut d)?;
        skip(&mut d, 675); // range proof
        skip(&mut d, 64); // signature
        return Ok(Output { receiver_public_key, message });
    }
}

impl Decodable for OutputMessage {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(&mut d)?;
        let standard_fields =
            if features & (OutputFeatures::StandardFieldsFeatureBit as u8) != 0 {
                let pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
                let key_exchange_pubkey = PublicKey::from_slice(&pubkey_bytes)?;
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
            skip_array(&mut d, | d2 | { skip(d2, 1) })
        }
        return Ok(OutputMessage{features, standard_fields});
    }
}
