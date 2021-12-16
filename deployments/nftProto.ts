const { bsv } = require('scryptlib')
const { toBigIntLE } = require("./common");
const ProtoHeader = require('./protoheader')

const NftProto = module.exports

NftProto.PROTO_TYPE = 3
NftProto.PROTO_VERSION = 1

NftProto.BURN_ADDRESS = Buffer.alloc(20, 0)

const OP_TRANSFER = 1
const OP_UNLOCK_FROM_CONTRACT = 2

// <type specific data> + <proto header>
//<nft type specific data> = <metaid_outpoint(36 bytes)> + <is_genesis(1 byte)> + <address(20 bytes)> + <totalSupply(8 bytes) + <tokenIndex(8 bytes)> + <genesisHash<20 bytes>) + <RABIN_PUBKEY_HASH_ARRAY_HASH(20 bytes)> + <sensibleID(36 bytes)>
const SENSIBLE_ID_LEN = 36
const RABIN_PUBKEY_HASH_ARRAY_HASH_LEN = 20
const GENESIS_HASH_LEN = 20
const TOKEN_INDEX_LEN = 8
const NFT_ID_LEN = 20
const TOTAL_SUPPLY_LEN = 8
const NFT_ADDRESS_LEN = 20
const GENESIS_FLAG_LEN = 1
const METAID_OUTPOINT_LEN = 36

const SENSIBLE_ID_OFFSET = ProtoHeader.HEADER_LEN + SENSIBLE_ID_LEN
const RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET = SENSIBLE_ID_OFFSET + RABIN_PUBKEY_HASH_ARRAY_HASH_LEN
const GENESIS_HASH_OFFSET = RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET + GENESIS_HASH_LEN
const TOKEN_INDEX_OFFSET = GENESIS_HASH_OFFSET + TOKEN_INDEX_LEN
const TOTAL_SUPPLY_OFFSET = TOKEN_INDEX_OFFSET + TOTAL_SUPPLY_LEN
const NFT_ADDRESS_OFFSET = TOTAL_SUPPLY_OFFSET + NFT_ADDRESS_LEN
const GENESIS_FLAG_OFFSET = NFT_ADDRESS_OFFSET + GENESIS_FLAG_LEN
const METAID_OUTPOINT_OFFSET = GENESIS_FLAG_OFFSET + METAID_OUTPOINT_LEN

const DATA_LEN = METAID_OUTPOINT_OFFSET

NftProto.getSensibleID = function (script: Buffer) {
  return script.subarray(script.length - SENSIBLE_ID_OFFSET, script.length - SENSIBLE_ID_OFFSET + SENSIBLE_ID_LEN)
}

NftProto.getRabinPubKeyHashArrayHash = function (script: Buffer) {
  return script.subarray(script.length - RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET, script.length - RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET + RABIN_PUBKEY_HASH_ARRAY_HASH_LEN)
}

NftProto.getGenesisHash = function (script: Buffer) {
  return script.subarray(script.length - GENESIS_HASH_OFFSET, script.length - GENESIS_HASH_OFFSET + GENESIS_HASH_LEN)
}

NftProto.getTokenIndex = function (script: Buffer) {
  return script.readBigUInt64LE(script.length - TOKEN_INDEX_OFFSET)
}

NftProto.getNftID = function (script: Buffer) {
  return bsv.crypto.Hash.sha256ripemd160(script.subarray(script.length - TOKEN_INDEX_OFFSET, script.length - ProtoHeader.HEADER_LEN))
}

NftProto.getTotalSupply = function (script: Buffer) {
  return script.readBigUInt64LE(script.length - TOTAL_SUPPLY_OFFSET)
}

NftProto.getNftAddress = function (script: Buffer) {
  return script.subarray(script.length - NFT_ADDRESS_OFFSET, script.length - NFT_ADDRESS_OFFSET + NFT_ADDRESS_LEN)
}

NftProto.getGenesisFlag = function (script: Buffer) {
  return script.readUIntLE(script.length - GENESIS_FLAG_OFFSET, GENESIS_FLAG_LEN)
}

NftProto.getContractCode = function (script: Buffer) {
  // contract code include op_return
  return script.subarray(0, script.length - DATA_LEN - 2)
}

NftProto.getContractCodeHash = function (script) {
  return bsv.crypto.Hash.sha256ripemd160(NftProto.getContractCode(script))
}

NftProto.getNewNftScript = function (script: Buffer, addressBuf: Buffer) {
  return Buffer.concat([
    script.subarray(0, script.length - NFT_ADDRESS_OFFSET),
    addressBuf,
    script.subarray(script.length - NFT_ADDRESS_OFFSET + NFT_ADDRESS_LEN, script.length)
  ])
}

NftProto.getNewGenesisScript = function (script: Buffer, sensibleID: Buffer, tokenIndex: number) {
  const indexBuf = Buffer.alloc(8, 0)
  indexBuf.writeBigUInt64LE(BigInt(tokenIndex))
  return Buffer.concat([
    script.subarray(0, script.length - TOKEN_INDEX_OFFSET),
    indexBuf,
    script.subarray(script.length - GENESIS_HASH_OFFSET, script.length - SENSIBLE_ID_OFFSET),
    sensibleID,
    script.subarray(script.length - ProtoHeader.HEADER_LEN, script.length)
  ])
}
