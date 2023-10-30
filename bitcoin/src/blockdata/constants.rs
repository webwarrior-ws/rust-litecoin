// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;

use bitcoin_internals::impl_array_newtype;
use hex_lit::hex;

use crate::hashes::{Hash, sha256d};
use crate::blockdata::script;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::locktime::absolute;
use crate::blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn, Sequence};
use crate::blockdata::block::{self, Block};
use crate::blockdata::witness::Witness;
use crate::network::constants::Network;
use crate::pow::CompactTarget;
use crate::internal_macros::impl_bytes_newtype;

/// The maximum allowable sequence number
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average
pub const TARGET_BLOCK_SPACING: u32 = 150;
/// How many blocks between diffchanges
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges
pub const DIFFCHANGE_TIMESPAN: u32 = 150 * 2016;
/// The maximum allowed weight for a block, see BIP 141 (network rule)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 48; // 0x30
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 50; // 0x32
/// Test (testnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (testnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 58; // 0x3a
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 840_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;
/// In Bitcoind this is insanely described as ~((u256)0 >> 32)
//pub fn max_target(_: Network) -> Uint256 {
//    Uint256::from_u64(0xFFFF).unwrap() << 208
//}

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub const MAX_MONEY: u64 = 84_000_000 * COIN_VALUE;

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block.
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
        mw_tx: None
    };

    // Inputs
    let in_script = script::Builder::new().push_int(486604799)
                                          .push_int_non_minimal(4)
                                          .push_slice(core::convert::TryInto::<[u8; 64]>::try_into("NY Times 05/Oct/2011 Steve Jobs, Apple’s Visionary, Dies at 56".as_bytes()).unwrap())
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9");
    let out_script = script::Builder::new()
        .push_slice(script_bytes)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 50 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Bitcoin => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1317972665,
                    bits: CompactTarget::from_consensus(0x1e0ffff0),
                    nonce: 2084524493
                },
                txdata,
            }
        }
        Network::Testnet => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1486949366,
                    bits: CompactTarget::from_consensus(0x1e0ffff0),
                    nonce: 293345
                },
                txdata,
            }
        }
        Network::Signet => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1598918400,
                    bits: CompactTarget::from_consensus(0x1e0377ae),
                    nonce: 52613770
                },
                txdata,
            }
        }
        Network::Regtest => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1296688602,
                    bits: CompactTarget::from_consensus(0x207fffff),
                    nonce: 2
                },
                txdata,
            }
        }
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet bitcoin.
    pub const BITCOIN: Self = Self([111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247, 79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0]);
    /// `ChainHash` for testnet bitcoin.
    pub const TESTNET: Self = Self([67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174, 186, 121, 151, 32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0]);
    /// `ChainHash` for signet bitcoin.
    pub const SIGNET: Self = Self([246, 30, 238, 59, 99, 163, 128, 164, 119, 160, 99, 175, 50, 178, 187, 201, 124, 159, 249, 240, 31, 44, 66, 37, 233, 115, 152, 129, 8, 0, 0, 0]);
    /// `ChainHash` for regtest bitcoin.
    pub const REGTEST: Self = Self([6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94, 51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::BITCOIN, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::network::constants::Network;
    use crate::consensus::encode::serialize;
    use crate::blockdata::locktime::absolute;
    use crate::internal_macros::hex;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("4341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac"));
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(gen.wtxid().to_string(), "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    }

    #[test]
    #[ignore = "Wrong test data for Litecoin"]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");

        assert_eq!(gen.header.time, 1486949366);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 293345);
        assert_eq!(gen.header.block_hash().to_string(), "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2");
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
        assert_eq!(gen.header.time, 1486949366);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 293345);
        assert_eq!(gen.header.block_hash().to_string(), "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0");
    }

    #[test]
    fn signet_genesis_full_block() {
        // Litecoin: disabled test as LTC has no signet
        // let gen = genesis_block(Network::Signet);
        // assert_eq!(gen.header.version, 1);
        // assert_eq!(gen.header.prev_blockhash, Default::default());
        // assert_eq!(format!("{:x}", gen.header.merkle_root),
        //           "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9".to_string());
        // assert_eq!(gen.header.time, 1598918400);
        // assert_eq!(gen.header.bits, 0x1e0377ae);
        // assert_eq!(gen.header.nonce, 52613770);
        // assert_eq!(format!("{:x}", gen.header.block_hash()),
        //            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6".to_string());
    }
}

