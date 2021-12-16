import { Buffer } from 'buffer';
import { expect } from 'chai'

import {
    bsv,
    getPreimage,
    toHex,
    SigHashPreimage,
    signTx,
    PubKey,
    Sig,
    Bytes,
    Ripemd160,
} from 'scryptlib'
const {
    inputSatoshis,
    dummyTxId,
} = require('../../helper');

const {
    privateKey,
    privateKey2,
} = require('../../privateKey');
import TokenProto = require('../../deployments/tokenProto');

const Common = require('../../deployments/common')
const Proto = require('../../deployments/protoheader')
const toBufferLE = Common.toBufferLE
const NftProto = require('../../deployments/nftProto')

const addOutput = Common.addOutput
const genContract = Common.genContract

const address1 = privateKey.toAddress()
const address2 = privateKey2.toAddress()

const OP_RETURN = Buffer.from('6a', 'hex')

// init contract
const USE_DESC = false
const USE_RELEASE = false
const Genesis = genContract('nftGenesis', USE_DESC, USE_RELEASE)
const Nft = genContract('nft', USE_DESC, USE_RELEASE)
const UnlockContractCheck = genContract('nftUnlockContractCheck', USE_DESC, USE_RELEASE)
const NftSell = genContract('nftSell', USE_DESC, USE_RELEASE)
const NftSellForToken = genContract('nftSellForToken', USE_DESC, USE_RELEASE)
const TokenBuyForNft = genContract('tokenBuyForNft', USE_DESC, USE_RELEASE)
const Token = genContract('token', true, false)

const rabinPubKeyIndexArray = Common.rabinPubKeyIndexArray
const rabinPubKeyVerifyArray = Common.rabinPubKeyVerifyArray
const rabinPubKeyHashArray = Common.rabinPubKeyHashArray
const rabinPubKeyHashArrayHash = Common.rabinPubKeyHashArrayHash

const genesisFlag = Common.getUInt8Buf(1)
const nonGenesisFlag = Common.getUInt8Buf(0)
const nftType = Common.getUInt32Buf(NftProto.PROTO_TYPE)
const nftVersion = Common.getUInt32Buf(NftProto.PROTO_VERSION)
const PROTO_FLAG = Proto.PROTO_FLAG
const metaidOutpoint = Buffer.alloc(36, 0)
export const genesisTxId = dummyTxId
export const genesisOutputIndex = 119
export const sensibleID = Buffer.concat([
    Common.getTxIdBuf(genesisTxId),
    Common.getUInt32Buf(genesisOutputIndex),
])

export function addInput(tx, lockingScript, outputIndex, prevouts, prevTxId = null, satoshis = null) {
    if (prevTxId === null) {
        prevTxId = dummyTxId
    }
    if (satoshis === null) {
        satoshis = inputSatoshis
    }
    tx.addInput(new bsv.Transaction.Input({
        prevTxId: prevTxId,
        outputIndex: outputIndex,
        script: ''
    }), lockingScript, satoshis)
    prevouts.push(Common.getTxIdBuf(prevTxId))
    prevouts.push(Common.getUInt32Buf(outputIndex))
}

let unlockContractCodeHashArray
export function initContractHash() {
    const unlockContract = new UnlockContractCheck()
    const code = Buffer.concat([unlockContract.lockingScript.toBuffer(), OP_RETURN])
    const hash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex')
    const unlockContractCodeHash = new Bytes(hash)
    unlockContractCodeHashArray = [unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash]
}

export function createNftGenesisContract(totalSupply: number, tokenIndex: number, sensibleID: Buffer) {
    const issuerPubKey = privateKey.publicKey
    const genesis = new Genesis(new PubKey(toHex(issuerPubKey)))
    const oracleData = Buffer.concat([
        Buffer.alloc(36, 0), // metaidOutpoint
        genesisFlag,
        Buffer.alloc(20, 0), // address
        Common.getUInt64Buf(totalSupply),
        Common.getUInt64Buf(tokenIndex),
        Buffer.alloc(20, 0), // genesisHash
        rabinPubKeyHashArrayHash,
        sensibleID, // sensibleID
        nftVersion,
        nftType,
        PROTO_FLAG
    ])
    genesis.setDataPart(oracleData.toString('hex'))
    return genesis
}

export function createNftContract(totalSupply: number, tokenIndex: number, genesisHash: Buffer, addressBuf: Buffer, sensID:any=sensibleID) {
    const nft = new Nft(unlockContractCodeHashArray)
    const oracleData = Buffer.concat([
        metaidOutpoint,
        nonGenesisFlag,
        addressBuf,
        Common.getUInt64Buf(totalSupply),
        Common.getUInt64Buf(tokenIndex),
        genesisHash,
        rabinPubKeyHashArrayHash,
        sensID,
        nftVersion,
        nftType,
        PROTO_FLAG
    ])
    nft.setDataPart(oracleData.toString('hex'))
    return nft
}

export function transferNft(totalSupply: number, tokenIndex: number, options: any = {}) {
    const genesisHash = options.genesisHash || Buffer.alloc(20, 0)
    const nft = createNftContract(totalSupply, tokenIndex, genesisHash, address1.hashBuffer)

    const tx = bsv.Transaction()
    // input
    let prevouts = []
    addInput(tx, nft.lockingScript, 0, prevouts)
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    const nft2 = createNftContract(totalSupply, tokenIndex, genesisHash, address2.hashBuffer)
    addOutput(tx, nft2.lockingScript, inputSatoshis)

    if (options.replicateNft) {
        addOutput(tx, nft2.lockingScript, inputSatoshis)
    }
    addOutput(tx, bsv.Script.buildPublicKeyHashOut(address1), inputSatoshis)

    const preimage = getPreimage(tx, nft.lockingScript.toASM(), inputSatoshis, 0)
    const sig = signTx(tx, privateKey, nft.lockingScript.toASM(), inputSatoshis, 0)

    const txContext = {
        tx: tx,
        inputIndex: 0,
        inputSatoshis: inputSatoshis
    }

    const prevNftAddress = address2.hashBuffer
    let scriptBuf = NftProto.getNewNftScript(nft.lockingScript.toBuffer(), prevNftAddress)
    if (options.prevScriptBuf) {
        scriptBuf = options.prevScriptBuf
    }
    const [rabinMsg, rabinPaddingArray, rabinSigArray] = Common.createRabinMsg(options.prevTxId || dummyTxId, options.prevOutputIndex || 0, inputSatoshis, scriptBuf, dummyTxId)

    const genesisScriptHex = options.genesisScriptHex || ''
    const result = nft.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevoutsBuf.toString('hex')),
        new Bytes(rabinMsg.toString('hex')),
        rabinPaddingArray,
        rabinSigArray,
        rabinPubKeyIndexArray,
        Common.rabinPubKeyVerifyArray,
        new Bytes(Common.rabinPubKeyHashArray.toString('hex')),
        new Bytes(prevNftAddress.toString('hex')),
        new Bytes(genesisScriptHex),
        new PubKey(toHex(privateKey.publicKey)),
        new Sig(toHex(sig)),
        new Bytes(address2.hashBuffer.toString('hex')), // receiver
        inputSatoshis, // nftOutputSatoshis
        new Bytes(''), // opReturnScript
        new Ripemd160(address1.hashBuffer.toString('hex')), // change address
        inputSatoshis, // change satoshis
        0, // checkInputIndex
        new Bytes(''), // checkScriptTx
        0, // lockContractInputIndex,
        new Bytes(''), // lockContractTx
        1, // op
    ).verify(txContext)

    if (options.expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

export function createNftSellTx(senderAddress: bsv.Address, sellSatoshis: number, nftCodeHash: string, nftID: string) {
    const tx = new bsv.Transaction()
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, [])
    const nftSell = new NftSell(new Ripemd160(senderAddress.hashBuffer.toString('hex')), sellSatoshis, new Bytes(nftCodeHash), new Bytes(nftID))
    const sellScript = nftSell.lockingScript
    tx.addOutput(new bsv.Transaction.Output({
        script: sellScript,
        satoshis: inputSatoshis
    }))

    return [nftSell, tx]
}

export function createNftSellForTokenTx(senderAddress: bsv.Address, tokenAmount: BigInt, tokenID: string, tokenCodeHash: string) {
    const tx = new bsv.Transaction()
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, [])
    const nftSell = new NftSellForToken(new Ripemd160(senderAddress.hashBuffer.toString('hex')), tokenAmount, new Bytes(tokenID), new Bytes(tokenCodeHash))
    const sellScript = nftSell.lockingScript
    tx.addOutput(new bsv.Transaction.Output({
        script: sellScript,
        satoshis: inputSatoshis
    }))

    return [nftSell, tx]
}

export function createTokenBuyForNftTx(senderAddress: bsv.Address, nftID: string, nftCodeHash: string) {
    const tx = new bsv.Transaction()
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, [])
    const tokenBuy = new TokenBuyForNft(new Ripemd160(senderAddress.hashBuffer.toString('hex')), new Bytes(nftID), new Bytes(nftCodeHash))
    tx.addOutput(new bsv.Transaction.Output({
        script: tokenBuy.lockingScript,
        satoshis: inputSatoshis
    }))

    return [tokenBuy, tx]
}

export function createUnlockContractCheck(nftCodeHash: string, nftID: string) {
    const tx = new bsv.Transaction()
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, [])
    const nftUnlockContractCheck = new UnlockContractCheck()
    nftUnlockContractCheck.setDataPart(nftCodeHash + nftID)

    const sellScript = nftUnlockContractCheck.lockingScript
    tx.addOutput(new bsv.Transaction.Output({
        script: sellScript,
        satoshis: inputSatoshis
    }))

    return [nftUnlockContractCheck, tx]
}

export function unlockUnlockContractCheck(unlockContractCheck, checkInputIndex: number, tx, nftInputIndex: number, nftScript: Buffer, prevoutsBuf: Buffer, nftOutputIndex: Number, nftOutputAddress: Buffer, nftOutputSatoshis: number, expected) {
    const nOutputs = tx.outputs.length;
    const preimage = getPreimage(tx, unlockContractCheck.lockingScript.toASM(), inputSatoshis, checkInputIndex)
    const txContext =  {
      tx: tx,
      inputIndex: checkInputIndex,
      inputSatoshis: inputSatoshis
    }

    const nftInput = tx.inputs[nftInputIndex]

    const [rabinMsg, rabinPaddingArray, rabinSigArray] = Common.createRabinMsg(nftInput.prevTxId, nftInput.outputIndex, nftInput.output.satoshis, nftInput.output.script.toBuffer())

    let otherOutputArray = Buffer.alloc(0)
    for (let i = 0; i < nOutputs; i++) {
        if (i !== nftOutputIndex) {
            const output = tx.outputs[i].toBufferWriter().toBuffer()
            otherOutputArray = Buffer.concat([
                otherOutputArray,
                Common.getUInt32Buf(output.length),
                output
            ])
        }
    }

    const result = unlockContractCheck.unlock(
        new SigHashPreimage(toHex(preimage)),
        nftInputIndex,
        new Bytes(nftScript.toString('hex')),
        new Bytes(prevoutsBuf.toString('hex')),
        new Bytes(rabinMsg.toString('hex')),
        rabinPaddingArray,
        rabinSigArray,
        rabinPubKeyIndexArray,
        Common.rabinPubKeyVerifyArray,
        new Bytes(Common.rabinPubKeyHashArray.toString('hex')),
        nOutputs,
        nftOutputIndex,
        new Bytes(nftOutputAddress.toString('hex')),
        nftOutputSatoshis,
        new Bytes(otherOutputArray.toString('hex')),
    ).verify(txContext)

    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

export function unlockNftSell(nftSell, tx, inputIndex: number, expected: boolean=true) {

    const sigtype = bsv.crypto.Signature.SIGHASH_SINGLE | bsv.crypto.Signature.SIGHASH_FORKID
    const preimage = getPreimage(tx, nftSell.lockingScript.toASM(), inputSatoshis, inputIndex, sigtype)

    const txContext = {
        tx: tx,
        inputIndex,
        inputSatoshis,
    }
    const result = nftSell.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(''),
        new PubKey(Buffer.alloc(33, 0).toString('hex')),
        new Sig(Buffer.alloc(72, 0).toString('hex')),
        0,
        1
    ).verify(txContext)

    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

export function unlockNftSellForToken(nftSell, tx, inputIndex: number, prevoutsBuf: Buffer, tokenScript, expected: boolean=true) {

    const sigtype = bsv.crypto.Signature.SIGHASH_SINGLE | bsv.crypto.Signature.SIGHASH_FORKID
    const preimage = getPreimage(tx, nftSell.lockingScript.toASM(), inputSatoshis, inputIndex, sigtype)

    const [tokenRabinMsg, tokenRabinPaddingArray, tokenRabinSigArray] = Common.createRabinMsg(dummyTxId, 0, inputSatoshis, tokenScript.toBuffer())

    const txContext = {
        tx: tx,
        inputIndex,
        inputSatoshis,
    }
    const result = nftSell.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevoutsBuf.toString('hex')),
        rabinPubKeyIndexArray,
        rabinPubKeyVerifyArray,
        new Bytes(rabinPubKeyHashArray.toString('hex')),
        new Bytes(tokenScript.toBuffer().toString('hex')),
        new Bytes(tokenRabinMsg.toString('hex')),
        tokenRabinPaddingArray,
        tokenRabinSigArray,
        new Bytes(''),
        new PubKey(Buffer.alloc(33, 0).toString('hex')),
        new Sig(Buffer.alloc(72, 0).toString('hex')),
        0,
        inputSatoshis,
        1
    ).verify(txContext)

    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

export function unlockTokenBuyForNft(tokenBuy, tx, inputIndex: number, prevoutsBuf: Buffer, nftScript, expected: boolean=true) {

    const sigtype = bsv.crypto.Signature.SIGHASH_SINGLE | bsv.crypto.Signature.SIGHASH_FORKID
    const preimage = getPreimage(tx, tokenBuy.lockingScript.toASM(), inputSatoshis, inputIndex, sigtype)

    const [rabinMsg, rabinPaddingArray, rabinSigArray] = Common.createRabinMsg(dummyTxId, 0, inputSatoshis, nftScript.toBuffer())

    const txContext = {
        tx: tx,
        inputIndex,
        inputSatoshis,
    }
    const result = tokenBuy.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevoutsBuf.toString('hex')),
        rabinPubKeyIndexArray,
        rabinPubKeyVerifyArray,
        new Bytes(rabinPubKeyHashArray.toString('hex')),
        new Bytes(nftScript.toBuffer().toString('hex')),
        new Bytes(rabinMsg.toString('hex')),
        rabinPaddingArray,
        rabinSigArray,
        new Bytes(''),
        new PubKey(Buffer.alloc(33, 0).toString('hex')),
        new Sig(Buffer.alloc(72, 0).toString('hex')),
        0,
        inputSatoshis,
        1
    ).verify(txContext)

    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

export function unlockNftFromContract(totalSupply: number, tokenIndex: number, options:any={}) {

    const genesisHash = options.genesisHash || Buffer.alloc(20, 0)
    let nft = createNftContract(totalSupply, tokenIndex, genesisHash, address1.hashBuffer)

    const nftCodeHash = NftProto.getContractCodeHash(nft.lockingScript.toBuffer()).toString('hex')
    const nftID = NftProto.getNftID(nft.lockingScript.toBuffer()).toString('hex')

    const sellSatoshis = inputSatoshis

    const [nftSellContract, nftSellTx] = createNftSellTx(address1, sellSatoshis, nftCodeHash, nftID)
    let lockContractHash = bsv.crypto.Hash.sha256ripemd160(nftSellContract.lockingScript.toBuffer())
    if (options.burn) {
        lockContractHash = NftProto.BURN_ADDRESS
    }
    nft = createNftContract(totalSupply, tokenIndex, genesisHash, lockContractHash)
    const [nftUnlockContractCheck, nftUnlockContractCheckTx] = createUnlockContractCheck(nftCodeHash, nftID)

    let prevouts = []
    const tx = bsv.Transaction()

    // input
    if (!options.burn) {
        addInput(tx, nftSellContract.lockingScript, 0, prevouts, nftSellTx.id)
    }
    const nftSellInputIndex = 0

    const nftInputIndex = tx.inputs.length
    addInput(tx, nft.lockingScript, 0, prevouts)
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address2), 0, prevouts)

    const checkInputIndex = tx.inputs.length
    addInput(tx, nftUnlockContractCheck.lockingScript, 0, prevouts, nftUnlockContractCheckTx.id)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    addOutput(tx, bsv.Script.buildPublicKeyHashOut(address1), sellSatoshis)
    const nft2 = createNftContract(totalSupply, tokenIndex, genesisHash, address2.hashBuffer)
    let nftOutputIndex = -1
    if (options.noNftOutput !== true) {
        addOutput(tx, nft2.lockingScript, inputSatoshis)
        nftOutputIndex = 1
    }
    // change bsv(optional)

    // unlock
    const preimage = getPreimage(tx, nft.lockingScript.toASM(), inputSatoshis, nftInputIndex)

    const txContext = {
        tx: tx,
        inputIndex: nftInputIndex,
        inputSatoshis,
    }

    const prevNftAddress = address2.hashBuffer
    let scriptBuf = NftProto.getNewNftScript(nft.lockingScript.toBuffer(), prevNftAddress)
    if (options.prevScriptBuf) {
        scriptBuf = options.prevScriptBuf
    }
    const [rabinMsg, rabinPaddingArray, rabinSigArray] = Common.createRabinMsg(options.prevTxId || dummyTxId, options.prevOutputIndex || 0, inputSatoshis, scriptBuf, dummyTxId)

    const result = nft.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevoutsBuf.toString('hex')),
        new Bytes(rabinMsg.toString('hex')),
        rabinPaddingArray,
        rabinSigArray,
        rabinPubKeyIndexArray,
        Common.rabinPubKeyVerifyArray,
        new Bytes(Common.rabinPubKeyHashArray.toString('hex')),
        new Bytes(prevNftAddress.toString('hex')),
        new Bytes(''),
        new PubKey(Buffer.alloc(33, 0).toString('hex')),
        new Sig(Buffer.alloc(72, 0).toString('hex')),
        new Bytes(''), // receiver
        0, // nftOutputSatoshis
        new Bytes(''), // opReturnScript
        new Ripemd160(Buffer.alloc(20, 0).toString('hex')), // change address
        0, // change satoshis
        checkInputIndex, // checkInputIndex
        new Bytes(nftUnlockContractCheckTx.toString('hex')), // checkScriptTx
        0, // lockContractInputIndex,
        new Bytes(nftSellTx.toString('hex')), // lockContractTx
        2, // op
    ).verify(txContext)

    if (options.expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }

    unlockUnlockContractCheck(nftUnlockContractCheck, checkInputIndex, tx, nftInputIndex, nft.lockingScript.toBuffer(), prevoutsBuf, nftOutputIndex, address2.hashBuffer, inputSatoshis, options.checkExpected)

    if (!options.burn) {
        unlockNftSell(nftSellContract, tx, nftSellInputIndex, true)
    }
}

export function issueNft(totalSupply: number, tokenIndex: number, options:any={}) {
    const tx = new bsv.Transaction()

    const genesis = createNftGenesisContract(totalSupply, tokenIndex, Buffer.alloc(36, 0))

    let prevouts = []
    const genesisTxId = dummyTxId
    const genesisOutputIndex = 0
    const sensibleID = Buffer.concat([
        Common.getTxIdBuf(genesisTxId),
        Common.getUInt32Buf(genesisOutputIndex)
    ])
    addInput(tx, genesis.lockingScript, genesisOutputIndex, prevouts)

    // output
    if (tokenIndex < totalSupply - 1) {
        const genesis2 = createNftGenesisContract(totalSupply, tokenIndex + 1, sensibleID)
        addOutput(tx, genesis2.lockingScript, inputSatoshis)
    }

    const newGenesisScriptBuf = NftProto.getNewGenesisScript(genesis.lockingScript.toBuffer(), sensibleID, 0)
    const genesisHash = bsv.crypto.Hash.sha256ripemd160(newGenesisScriptBuf)
    const nft = createNftContract(totalSupply, tokenIndex, genesisHash, address1.hashBuffer, sensibleID)
    addOutput(tx, nft.lockingScript, inputSatoshis)

    // unlock
    let inputIndex = 0
    const preimage = getPreimage(tx, genesis.lockingScript.toASM(), inputSatoshis, inputIndex)
    const sig = signTx(tx, privateKey, genesis.lockingScript.toASM(), inputSatoshis, inputIndex)

    const txContext = {
        tx: tx,
        inputIndex,
        inputSatoshis,
    }

    let rabinMsg = Buffer.alloc(0)
    let rabinPaddingArray = Array(Common.oracleVerifyNum).fill(new Bytes(''))
    let rabinSigArray = Array(Common.oracleVerifyNum).fill(0)
    if (tokenIndex > 0) {
        const scriptBuf = NftProto.getNewGenesisScript(genesis.lockingScript.toBuffer(), sensibleID, tokenIndex - 1)
        const res = Common.createRabinMsg(options.prevTxId || dummyTxId, options.prevOutputIndex || 0, inputSatoshis, scriptBuf, dummyTxId)
        rabinMsg = res[0]
        rabinPaddingArray = res[1]
        rabinSigArray = res[2]
    }

    // unlock
    const result = genesis.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Sig(toHex(sig)),
        new Bytes(rabinMsg.toString('hex')),
        rabinPaddingArray,
        rabinSigArray,
        rabinPubKeyIndexArray,
        Common.rabinPubKeyVerifyArray,
        new Bytes(Common.rabinPubKeyHashArray.toString('hex')),
        inputSatoshis,
        new Bytes(nft.lockingScript.toBuffer().toString('hex')),
        inputSatoshis,
        new Ripemd160(address1.hashBuffer.toString('hex')),
        0,
        new Bytes('')
    ).verify(txContext)

    if (options.expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createTokenContract(addressBuf: Buffer, amount: BigInt) {
    const tokenName = Buffer.alloc(20, 0)
    tokenName.write('test token name')
    const tokenSymbol = Buffer.alloc(10, 0)
    tokenSymbol.write('ttn')
    const genesisHash = Buffer.alloc(20, 0).toString('hex')
    const tokenSensibleID = Buffer.concat([
        Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse()),
        Common.getUInt32Buf(11),
    ]).toString('hex')
    const decimalNum = Buffer.from('08', 'hex')
    const tokenType = Common.getUInt32Buf(TokenProto.PROTO_TYPE)
    const tokenVersion = Common.getUInt32Buf(TokenProto.PROTO_VERSION)
    const transferCheckCodeHash = new Bytes(Buffer.alloc(20, 0).toString('hex'))
    const transferCheckCodeHashArray = [transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash]
    const token = new Token(transferCheckCodeHashArray, unlockContractCodeHashArray)
    const data = Buffer.concat([
        tokenName,
        tokenSymbol,
        nonGenesisFlag,
        decimalNum,
        addressBuf,
        Common.getUInt64Buf(amount),
        Buffer.from(genesisHash, 'hex'),
        rabinPubKeyHashArrayHash,
        Buffer.from(tokenSensibleID, 'hex'),
        tokenVersion,
        tokenType, // type
        PROTO_FLAG
    ])
    token.setDataPart(data.toString('hex'))
    return token
}

export function sellNftForToken(totalSupply: number, tokenIndex: number, options:any={}) {
    const sellerAddress = address1
    const buyerAddress = address2
    const genesisHash = options.genesisHash || Buffer.alloc(20, 0)
    const tokenAmount = BigInt(10000)

    let nft = createNftContract(totalSupply, tokenIndex, genesisHash, sellerAddress.hashBuffer)

    const nftCodeHash = NftProto.getContractCodeHash(nft.lockingScript.toBuffer()).toString('hex')
    const nftID = NftProto.getNftID(nft.lockingScript.toBuffer()).toString('hex')

    const token = createTokenContract(buyerAddress.hashBuffer, tokenAmount)
    const tokenID = TokenProto.getTokenID(token.lockingScript.toBuffer()).toString('hex')
    const tokenCodeHash = TokenProto.getContractCodeHash(token.lockingScript.toBuffer()).toString('hex')

    const [nftSellContract, nftSellTx] = createNftSellForTokenTx(address1, tokenAmount, tokenID, tokenCodeHash)
    let lockContractHash = bsv.crypto.Hash.sha256ripemd160(nftSellContract.lockingScript.toBuffer())
    nft = createNftContract(totalSupply, tokenIndex, genesisHash, lockContractHash)
    const [nftUnlockContractCheck, nftUnlockContractCheckTx] = createUnlockContractCheck(nftCodeHash, nftID)

    let prevouts = []
    const tx = bsv.Transaction()

    // input
    // nftSellForToken
    addInput(tx, nftSellContract.lockingScript, 0, prevouts, nftSellTx.id)

    // tokenBuyForNft
    const [tokenBuyForNft, tokenBuyForNftTx] = createTokenBuyForNftTx(buyerAddress, nftID, nftCodeHash)
    addInput(tx, tokenBuyForNft.lockingScript, 0, prevouts)

    // nft
    const nftInputIndex = tx.inputs.length
    addInput(tx, nft.lockingScript, 0, prevouts)

    // token
    addInput(tx, token.lockingScript, 0, prevouts)

    // nftCheck
    const checkInputIndex = tx.inputs.length
    addInput(tx, nftUnlockContractCheck.lockingScript, 0, prevouts, nftUnlockContractCheckTx.id)

    // tokenCheck
    let script = token.lockingScript
    addInput(tx, script, 0, prevouts)

    // bsv
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address2), 0, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output

    // token
    let scriptBuf = TokenProto.getNewTokenScript(token.lockingScript.toBuffer(), sellerAddress.hashBuffer, tokenAmount)
    addOutput(tx, bsv.Script.fromBuffer(scriptBuf), inputSatoshis)

    // nft
    const nft2 = createNftContract(totalSupply, tokenIndex, genesisHash, address2.hashBuffer)
    addOutput(tx, nft2.lockingScript, inputSatoshis)
    const nftOutputIndex = 1

    // change bsv(optional)

    // unlock
    const preimage = getPreimage(tx, nft.lockingScript.toASM(), inputSatoshis, nftInputIndex)

    const txContext = {
        tx: tx,
        inputIndex: nftInputIndex,
        inputSatoshis,
    }

    const prevNftAddress = address2.hashBuffer
    scriptBuf = NftProto.getNewNftScript(nft.lockingScript.toBuffer(), prevNftAddress)
    const [rabinMsg, rabinPaddingArray, rabinSigArray] = Common.createRabinMsg(options.prevTxId || dummyTxId, options.prevOutputIndex || 0, inputSatoshis, scriptBuf, dummyTxId)

    const result = nft.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevoutsBuf.toString('hex')),
        new Bytes(rabinMsg.toString('hex')),
        rabinPaddingArray,
        rabinSigArray,
        rabinPubKeyIndexArray,
        Common.rabinPubKeyVerifyArray,
        new Bytes(Common.rabinPubKeyHashArray.toString('hex')),
        new Bytes(prevNftAddress.toString('hex')),
        new Bytes(''),
        new PubKey(Buffer.alloc(33, 0).toString('hex')),
        new Sig(Buffer.alloc(72, 0).toString('hex')),
        new Bytes(''), // receiver
        0, // nftOutputSatoshis
        new Bytes(''), // opReturnScript
        new Ripemd160(Buffer.alloc(20, 0).toString('hex')), // change address
        0, // change satoshis
        checkInputIndex, // checkInputIndex
        new Bytes(nftUnlockContractCheckTx.toString('hex')), // checkScriptTx
        0, // lockContractInputIndex,
        new Bytes(nftSellTx.toString('hex')), // lockContractTx
        2, // op
    ).verify(txContext)

    if (options.expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }

    unlockUnlockContractCheck(nftUnlockContractCheck, checkInputIndex, tx, nftInputIndex, nft.lockingScript.toBuffer(), prevoutsBuf, nftOutputIndex, address2.hashBuffer, inputSatoshis, options.checkExpected)

    unlockNftSellForToken(nftSellContract, tx, 0, prevoutsBuf, token.lockingScript)

    unlockTokenBuyForNft(tokenBuyForNft, tx, 1, prevoutsBuf, nft.lockingScript)
}