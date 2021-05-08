"use strict";
exports.__esModule = true;
var baddress = require("./address");
var bufferutils_1 = require("./bufferutils");
var classify = require("./classify");
var bcrypto = require("./crypto");
var ECPair = require("./ecpair");
var networks = require("./networks");
var payments = require("./payments");
var bscript = require("./script");
var script_1 = require("./script");
var transaction_1 = require("./transaction");
var types = require("./types");
var typeforce = require('typeforce');
var SCRIPT_TYPES = classify.types;
var PREVOUT_TYPES = new Set([
    // Raw
    'p2pkh',
    'p2pk',
    'p2wpkh',
    'p2ms',
    'htlc',
    // P2SH wrapped
    'p2sh-htlc',
    'p2sh-p2pkh',
    'p2sh-p2pk',
    'p2sh-p2wpkh',
    'p2sh-p2ms',
    // P2WSH wrapped
    'p2wsh-p2pkh',
    'p2wsh-p2pk',
    'p2wsh-p2ms',
    // P2SH-P2WSH wrapper
    'p2sh-p2wsh-p2pkh',
    'p2sh-p2wsh-p2pk',
    'p2sh-p2wsh-p2ms',
]);
function tfMessage(type, value, message) {
    try {
        typeforce(type, value);
    }
    catch (err) {
        throw new Error(message);
    }
}
function txIsString(tx) {
    return typeof tx === 'string' || tx instanceof String;
}
function txIsTransaction(tx) {
    return tx instanceof transaction_1.Transaction;
}
var TransactionBuilder = /** @class */ (function () {
    // WARNING: maximumFeeRate is __NOT__ to be relied on,
    //          it's just another potential safety mechanism (safety in-depth)
    function TransactionBuilder(network, maximumFeeRate) {
        if (network === void 0) { network = networks.bitcoin; }
        if (maximumFeeRate === void 0) { maximumFeeRate = 2500; }
        this.network = network;
        this.maximumFeeRate = maximumFeeRate;
        this.__PREV_TX_SET = {};
        this.__INPUTS = [];
        this.__TX = new transaction_1.Transaction();
        this.__TX.version = 2;
        this.__TX.nTime = Math.floor((new Date().getTime()) / 1000);
        this.__USE_LOW_R = false;
    }
    TransactionBuilder.fromTransaction = function (transaction, network) {
        var txb = new TransactionBuilder(network);
        // Copy transaction fields
        txb.setVersion(transaction.version);
        txb.setLockTime(transaction.locktime);
        txb.setNTime(transaction.nTime);
        // Copy outputs (done first to avoid signature invalidation)
        transaction.outs.forEach(function (txOut) {
            txb.addOutput(txOut.script, txOut.value);
        });
        // Copy inputs
        transaction.ins.forEach(function (txIn) {
            txb.__addInputUnsafe(txIn.hash, txIn.index, {
                sequence: txIn.sequence,
                script: txIn.script,
                witness: txIn.witness
            });
        });
        // fix some things not possible through the public API
        txb.__INPUTS.forEach(function (input, i) {
            fixMultisigOrder(input, transaction, i);
        });
        return txb;
    };
    TransactionBuilder.prototype.setLowR = function (setting) {
        typeforce(typeforce.maybe(typeforce.Boolean), setting);
        if (setting === undefined) {
            setting = true;
        }
        this.__USE_LOW_R = setting;
        return setting;
    };
    TransactionBuilder.prototype.setLockTime = function (locktime) {
        typeforce(types.UInt32, locktime);
        // if any signatures exist, throw
        if (this.__INPUTS.some(function (input) {
            if (!input.signatures)
                return false;
            return input.signatures.some(function (s) { return s !== undefined; });
        })) {
            throw new Error('No, this would invalidate signatures');
        }
        this.__TX.locktime = locktime;
    };
    TransactionBuilder.prototype.setNTime = function (time) {
        typeforce(types.UInt32, time);
        this.__TX.nTime = time;
    };
    TransactionBuilder.prototype.addNTime = function (time) {
        this.__TX.nTime = this.__TX.nTime + time;
    };
    TransactionBuilder.prototype.setVersion = function (version) {
        typeforce(types.UInt32, version);
        this.__TX.version = version;
    };
    TransactionBuilder.prototype.addInput = function (txHash, vout, sequence, prevOutScript) {
        if (!this.__canModifyInputs()) {
            throw new Error('No, this would invalidate signatures');
        }
        var value;
        // is it a hex string?
        if (txIsString(txHash)) {
            // transaction hashs's are displayed in reverse order, un-reverse it
            txHash = bufferutils_1.reverseBuffer(Buffer.from(txHash, 'hex'));
            // is it a Transaction object?
        }
        else if (txIsTransaction(txHash)) {
            var txOut = txHash.outs[vout];
            prevOutScript = txOut.script;
            value = txOut.value;
            txHash = txHash.getHash(false);
        }
        return this.__addInputUnsafe(txHash, vout, {
            sequence: sequence,
            prevOutScript: prevOutScript,
            value: value
        });
    };
    TransactionBuilder.prototype.addOutput = function (scriptPubKey, value) {
        if (!this.__canModifyOutputs()) {
            throw new Error('No, this would invalidate signatures');
        }
        // Attempt to get a script if it's a base58 or bech32 address string
        if (typeof scriptPubKey === 'string') {
            scriptPubKey = baddress.toOutputScript(scriptPubKey, this.network);
        }
        return this.__TX.addOutput(scriptPubKey, value);
    };
    TransactionBuilder.prototype.build = function () {
        return this.__build(false);
    };
    TransactionBuilder.prototype.buildIncomplete = function () {
        return this.__build(true);
    };
    TransactionBuilder.prototype.sign = function (signParams, keyPair, redeemScript, hashType, witnessValue, witnessScript) {
        trySign(getSigningData(this.network, this.__INPUTS, this.__needsOutputs.bind(this), this.__TX, signParams, keyPair, redeemScript, hashType, witnessValue, witnessScript, this.__USE_LOW_R));
    };
    TransactionBuilder.prototype.__addInputUnsafe = function (txHash, vout, options) {
        if (transaction_1.Transaction.isCoinbaseHash(txHash)) {
            throw new Error('coinbase inputs not supported');
        }
        var prevTxOut = txHash.toString('hex') + ':' + vout;
        if (this.__PREV_TX_SET[prevTxOut] !== undefined)
            throw new Error('Duplicate TxOut: ' + prevTxOut);
        var input = {};
        // derive what we can from the scriptSig
        if (options.script !== undefined) {
            input = expandInput(options.script, options.witness || []);
        }
        // if an input value was given, retain it
        if (options.value !== undefined) {
            input.value = options.value;
        }
        // derive what we can from the previous transactions output script
        if (!input.prevOutScript && options.prevOutScript) {
            var prevOutType = void 0;
            if (!input.pubkeys && !input.signatures) {
                var expanded = expandOutput(options.prevOutScript);
                if (expanded.pubkeys) {
                    input.pubkeys = expanded.pubkeys;
                    input.signatures = expanded.signatures;
                }
                prevOutType = expanded.type;
            }
            input.prevOutScript = options.prevOutScript;
            input.prevOutType = prevOutType || classify.output(options.prevOutScript);
        }
        var vin = this.__TX.addInput(txHash, vout, options.sequence, options.scriptSig);
        this.__INPUTS[vin] = input;
        this.__PREV_TX_SET[prevTxOut] = true;
        return vin;
    };
    TransactionBuilder.prototype.__build = function (allowIncomplete) {
        if (!allowIncomplete) {
            if (!this.__TX.ins.length)
                throw new Error('Transaction has no inputs');
            if (!this.__TX.outs.length)
                throw new Error('Transaction has no outputs');
        }
        var tx = this.__TX.clone();
        // create script signatures from inputs
        this.__INPUTS.forEach(function (input, i) {
            if (!input.prevOutType && !allowIncomplete)
                throw new Error('Transaction is not complete');
            var result = build(input.prevOutType, input, allowIncomplete);
            if (!result) {
                if (!allowIncomplete && input.prevOutType === SCRIPT_TYPES.NONSTANDARD)
                    throw new Error('Unknown input type');
                if (!allowIncomplete)
                    throw new Error('Not enough information');
                return;
            }
            tx.setInputScript(i, result.input);
            tx.setWitness(i, result.witness);
        });
        if (!allowIncomplete) {
            // do not rely on this, its merely a last resort
            if (this.__overMaximumFees(tx.virtualSize())) {
                throw new Error('Transaction has absurd fees');
            }
        }
        return tx;
    };
    TransactionBuilder.prototype.__canModifyInputs = function () {
        return this.__INPUTS.every(function (input) {
            if (!input.signatures)
                return true;
            return input.signatures.every(function (signature) {
                if (!signature)
                    return true;
                var hashType = signatureHashType(signature);
                // if SIGHASH_ANYONECANPAY is set, signatures would not
                // be invalidated by more inputs
                return (hashType & transaction_1.Transaction.SIGHASH_ANYONECANPAY) !== 0;
            });
        });
    };
    TransactionBuilder.prototype.__needsOutputs = function (signingHashType) {
        if (signingHashType === transaction_1.Transaction.SIGHASH_ALL) {
            return this.__TX.outs.length === 0;
        }
        // if inputs are being signed with SIGHASH_NONE, we don't strictly need outputs
        // .build() will fail, but .buildIncomplete() is OK
        return (this.__TX.outs.length === 0 &&
            this.__INPUTS.some(function (input) {
                if (!input.signatures)
                    return false;
                return input.signatures.some(function (signature) {
                    if (!signature)
                        return false; // no signature, no issue
                    var hashType = signatureHashType(signature);
                    if (hashType & transaction_1.Transaction.SIGHASH_NONE)
                        return false; // SIGHASH_NONE doesn't care about outputs
                    return true; // SIGHASH_* does care
                });
            }));
    };
    TransactionBuilder.prototype.__canModifyOutputs = function () {
        var nInputs = this.__TX.ins.length;
        var nOutputs = this.__TX.outs.length;
        return this.__INPUTS.every(function (input) {
            if (input.signatures === undefined)
                return true;
            return input.signatures.every(function (signature) {
                if (!signature)
                    return true;
                var hashType = signatureHashType(signature);
                var hashTypeMod = hashType & 0x1f;
                if (hashTypeMod === transaction_1.Transaction.SIGHASH_NONE)
                    return true;
                if (hashTypeMod === transaction_1.Transaction.SIGHASH_SINGLE) {
                    // if SIGHASH_SINGLE is set, and nInputs > nOutputs
                    // some signatures would be invalidated by the addition
                    // of more outputs
                    return nInputs <= nOutputs;
                }
                return false;
            });
        });
    };
    TransactionBuilder.prototype.__overMaximumFees = function (bytes) {
        // not all inputs will have .value defined
        var incoming = this.__INPUTS.reduce(function (a, x) { return a + (x.value >>> 0); }, 0);
        // but all outputs do, and if we have any input value
        // we can immediately determine if the outputs are too small
        var outgoing = this.__TX.outs.reduce(function (a, x) { return a + x.value; }, 0);
        var fee = incoming - outgoing;
        var feeRate = fee / bytes;
        return feeRate > this.maximumFeeRate;
    };
    return TransactionBuilder;
}());
exports.TransactionBuilder = TransactionBuilder;
function expandInput(scriptSig, witnessStack, type, scriptPubKey) {
    if (scriptSig.length === 0 && witnessStack.length === 0)
        return {};
    if (!type) {
        var ssType = classify.input(scriptSig, true);
        var wsType = classify.witness(witnessStack, true);
        if (ssType === SCRIPT_TYPES.NONSTANDARD)
            ssType = undefined;
        if (wsType === SCRIPT_TYPES.NONSTANDARD)
            wsType = undefined;
        type = ssType || wsType;
    }
    switch (type) {
        case SCRIPT_TYPES.P2WPKH: {
            var _a = payments.p2wpkh({
                witness: witnessStack
            }), output = _a.output, pubkey = _a.pubkey, signature = _a.signature;
            return {
                prevOutScript: output,
                prevOutType: SCRIPT_TYPES.P2WPKH,
                pubkeys: [pubkey],
                signatures: [signature]
            };
        }
        case SCRIPT_TYPES.P2PKH: {
            var _b = payments.p2pkh({
                input: scriptSig
            }), output = _b.output, pubkey = _b.pubkey, signature = _b.signature;
            return {
                prevOutScript: output,
                prevOutType: SCRIPT_TYPES.P2PKH,
                pubkeys: [pubkey],
                signatures: [signature]
            };
        }
        case SCRIPT_TYPES.P2PK: {
            var signature = payments.p2pk({ input: scriptSig }).signature;
            return {
                prevOutType: SCRIPT_TYPES.P2PK,
                pubkeys: [undefined],
                signatures: [signature]
            };
        }
        case SCRIPT_TYPES.P2MS: {
            var _c = payments.p2ms({
                input: scriptSig,
                output: scriptPubKey
            }, { allowIncomplete: true }), m = _c.m, pubkeys = _c.pubkeys, signatures = _c.signatures;
            return {
                prevOutType: SCRIPT_TYPES.P2MS,
                pubkeys: pubkeys,
                signatures: signatures,
                maxSignatures: m
            };
        }
    }
    if (type === SCRIPT_TYPES.P2SH) {
        var _d = payments.p2sh({
            input: scriptSig,
            witness: witnessStack
        }), output = _d.output, redeem = _d.redeem;
        var outputType = classify.output(redeem.output);
        var expanded = expandInput(redeem.input, redeem.witness, outputType, redeem.output);
        if (!expanded.prevOutType)
            return {};
        return {
            prevOutScript: output,
            prevOutType: SCRIPT_TYPES.P2SH,
            redeemScript: redeem.output,
            redeemScriptType: expanded.prevOutType,
            witnessScript: expanded.witnessScript,
            witnessScriptType: expanded.witnessScriptType,
            pubkeys: expanded.pubkeys,
            signatures: expanded.signatures
        };
    }
    if (type === SCRIPT_TYPES.P2WSH) {
        var _e = payments.p2wsh({
            input: scriptSig,
            witness: witnessStack
        }), output = _e.output, redeem = _e.redeem;
        var outputType = classify.output(redeem.output);
        var expanded = void 0;
        if (outputType === SCRIPT_TYPES.P2WPKH) {
            expanded = expandInput(redeem.input, redeem.witness, outputType);
        }
        else {
            expanded = expandInput(bscript.compile(redeem.witness), [], outputType, redeem.output);
        }
        if (!expanded.prevOutType)
            return {};
        return {
            prevOutScript: output,
            prevOutType: SCRIPT_TYPES.P2WSH,
            witnessScript: redeem.output,
            witnessScriptType: expanded.prevOutType,
            pubkeys: expanded.pubkeys,
            signatures: expanded.signatures
        };
    }
    return {
        prevOutType: SCRIPT_TYPES.NONSTANDARD,
        prevOutScript: scriptSig
    };
}
// could be done in expandInput, but requires the original Transaction for hashForSignature
function fixMultisigOrder(input, transaction, vin) {
    if (input.redeemScriptType !== SCRIPT_TYPES.P2MS || !input.redeemScript)
        return;
    if (input.pubkeys.length === input.signatures.length)
        return;
    var unmatched = input.signatures.concat();
    input.signatures = input.pubkeys.map(function (pubKey) {
        var keyPair = ECPair.fromPublicKey(pubKey);
        var match;
        // check for a signature
        unmatched.some(function (signature, i) {
            // skip if undefined || OP_0
            if (!signature)
                return false;
            // TODO: avoid O(n) hashForSignature
            var parsed = bscript.signature.decode(signature);
            var hash = transaction.hashForSignature(vin, input.redeemScript, parsed.hashType);
            // skip if signature does not match pubKey
            if (!keyPair.verify(hash, parsed.signature))
                return false;
            // remove matched signature from unmatched
            unmatched[i] = undefined;
            match = signature;
            return true;
        });
        return match;
    });
}
function expandOutput(script, ourPubKey) {
    typeforce(types.Buffer, script);
    var type = classify.output(script);
    switch (type) {
        case SCRIPT_TYPES.HTLC: {
            if (!ourPubKey)
                return { type: type };
            return {
                type: type,
                pubkeys: [ourPubKey]
            };
        }
        case SCRIPT_TYPES.P2PKH: {
            if (!ourPubKey)
                return { type: type };
            // does our hash160(pubKey) match the output scripts?
            var pkh1 = payments.p2pkh({ output: script }).hash;
            var pkh2 = bcrypto.hash160(ourPubKey);
            if (!pkh1.equals(pkh2))
                return { type: type };
            return {
                type: type,
                pubkeys: [ourPubKey],
                signatures: [undefined]
            };
        }
        case SCRIPT_TYPES.P2WPKH: {
            if (!ourPubKey)
                return { type: type };
            // does our hash160(pubKey) match the output scripts?
            var wpkh1 = payments.p2wpkh({ output: script }).hash;
            var wpkh2 = bcrypto.hash160(ourPubKey);
            if (!wpkh1.equals(wpkh2))
                return { type: type };
            return {
                type: type,
                pubkeys: [ourPubKey],
                signatures: [undefined]
            };
        }
        case SCRIPT_TYPES.P2PK: {
            var p2pk = payments.p2pk({ output: script });
            return {
                type: type,
                pubkeys: [p2pk.pubkey],
                signatures: [undefined]
            };
        }
        case SCRIPT_TYPES.P2MS: {
            var p2ms = payments.p2ms({ output: script });
            return {
                type: type,
                pubkeys: p2ms.pubkeys,
                signatures: p2ms.pubkeys.map(function () { return undefined; }),
                maxSignatures: p2ms.m
            };
        }
    }
    return { type: type };
}
function prepareInput(input, ourPubKey, redeemScript, witnessScript) {
    if (redeemScript && witnessScript) {
        var p2wsh = payments.p2wsh({
            redeem: { output: witnessScript }
        });
        var p2wshAlt = payments.p2wsh({ output: redeemScript });
        var p2sh = payments.p2sh({ redeem: { output: redeemScript } });
        var p2shAlt = payments.p2sh({ redeem: p2wsh });
        // enforces P2SH(P2WSH(...))
        if (!p2wsh.hash.equals(p2wshAlt.hash))
            throw new Error('Witness script inconsistent with prevOutScript');
        if (!p2sh.hash.equals(p2shAlt.hash))
            throw new Error('Redeem script inconsistent with prevOutScript');
        var expanded = expandOutput(p2wsh.redeem.output, ourPubKey);
        if (!expanded.pubkeys)
            throw new Error(expanded.type +
                ' not supported as witnessScript (' +
                bscript.toASM(witnessScript) +
                ')');
        if (input.signatures && input.signatures.some(function (x) { return x !== undefined; })) {
            expanded.signatures = input.signatures;
        }
        var signScript = witnessScript;
        if (expanded.type === SCRIPT_TYPES.P2WPKH)
            throw new Error('P2SH(P2WSH(P2WPKH)) is a consensus failure');
        return {
            redeemScript: redeemScript,
            redeemScriptType: SCRIPT_TYPES.P2WSH,
            witnessScript: witnessScript,
            witnessScriptType: expanded.type,
            prevOutType: SCRIPT_TYPES.P2SH,
            prevOutScript: p2sh.output,
            hasWitness: true,
            signScript: signScript,
            signType: expanded.type,
            pubkeys: expanded.pubkeys,
            signatures: expanded.signatures,
            maxSignatures: expanded.maxSignatures
        };
    }
    if (redeemScript) {
        var expanded = expandOutput(redeemScript, ourPubKey);
        var payment = null;
        var paymentAlt = null;
        var paymentconst = void 0;
        if (expanded.type == SCRIPT_TYPES.P2SH) {
            paymentconst = payments.p2sh;
        }
        if (expanded.type == SCRIPT_TYPES.HTLC) {
            paymentconst = payments.htlc;
        }
        if (!paymentconst)
            throw new Error('non standart');
        payment = paymentconst({ redeem: { output: redeemScript } });
        if (paymentconst) {
            if (input.prevOutScript) {
                try {
                    paymentAlt = paymentconst({ output: input.prevOutScript });
                }
                catch (e) {
                    throw new Error('PrevOutScript must be P2SH');
                }
                if (!payment.hash.equals(paymentAlt.hash))
                    throw new Error('Redeem script inconsistent with prevOutScript');
            }
        }
        if (!expanded.pubkeys)
            throw new Error(expanded.type +
                ' not supported as redeemScript (' +
                bscript.toASM(redeemScript) +
                ')');
        if (input.signatures && input.signatures.some(function (x) { return x !== undefined; })) {
            expanded.signatures = input.signatures;
        }
        var signScript = redeemScript;
        if (expanded.type === SCRIPT_TYPES.P2WPKH) {
            signScript = payments.p2pkh({ pubkey: expanded.pubkeys[0] }).output;
        }
        return {
            redeemScript: redeemScript,
            redeemScriptType: expanded.type,
            prevOutType: expanded.type == SCRIPT_TYPES.HTLC ? SCRIPT_TYPES.HTLC : SCRIPT_TYPES.P2SH,
            prevOutScript: payment.output,
            hasWitness: expanded.type === SCRIPT_TYPES.P2WPKH,
            signScript: signScript,
            signType: expanded.type,
            pubkeys: expanded.pubkeys,
            signatures: expanded.signatures,
            maxSignatures: expanded.maxSignatures
        };
    }
    if (witnessScript) {
        var p2wsh = payments.p2wsh({ redeem: { output: witnessScript } });
        if (input.prevOutScript) {
            var p2wshAlt = payments.p2wsh({ output: input.prevOutScript });
            if (!p2wsh.hash.equals(p2wshAlt.hash))
                throw new Error('Witness script inconsistent with prevOutScript');
        }
        var expanded = expandOutput(p2wsh.redeem.output, ourPubKey);
        if (!expanded.pubkeys)
            throw new Error(expanded.type +
                ' not supported as witnessScript (' +
                bscript.toASM(witnessScript) +
                ')');
        if (input.signatures && input.signatures.some(function (x) { return x !== undefined; })) {
            expanded.signatures = input.signatures;
        }
        var signScript = witnessScript;
        if (expanded.type === SCRIPT_TYPES.P2WPKH)
            throw new Error('P2WSH(P2WPKH) is a consensus failure');
        return {
            witnessScript: witnessScript,
            witnessScriptType: expanded.type,
            prevOutType: SCRIPT_TYPES.P2WSH,
            prevOutScript: p2wsh.output,
            hasWitness: true,
            signScript: signScript,
            signType: expanded.type,
            pubkeys: expanded.pubkeys,
            signatures: expanded.signatures,
            maxSignatures: expanded.maxSignatures
        };
    }
    if (input.prevOutType && input.prevOutScript) {
        // embedded scripts are not possible without extra information
        if (input.prevOutType === SCRIPT_TYPES.HTLC)
            throw new Error('PrevOutScript is ' + input.prevOutType + ', requires redeemScript');
        if (input.prevOutType === SCRIPT_TYPES.P2SH)
            throw new Error('PrevOutScript is ' + input.prevOutType + ', requires redeemScript');
        if (input.prevOutType === SCRIPT_TYPES.P2WSH)
            throw new Error('PrevOutScript is ' + input.prevOutType + ', requires witnessScript');
        if (!input.prevOutScript)
            throw new Error('PrevOutScript is missing');
        var expanded = expandOutput(input.prevOutScript, ourPubKey);
        if (!expanded.pubkeys)
            throw new Error(expanded.type +
                ' not supported (' +
                bscript.toASM(input.prevOutScript) +
                ')');
        if (input.signatures && input.signatures.some(function (x) { return x !== undefined; })) {
            expanded.signatures = input.signatures;
        }
        var signScript = input.prevOutScript;
        if (expanded.type === SCRIPT_TYPES.P2WPKH) {
            signScript = payments.p2pkh({ pubkey: expanded.pubkeys[0] })
                .output;
        }
        return {
            prevOutType: expanded.type,
            prevOutScript: input.prevOutScript,
            hasWitness: expanded.type === SCRIPT_TYPES.P2WPKH,
            signScript: signScript,
            signType: expanded.type,
            pubkeys: expanded.pubkeys,
            signatures: expanded.signatures,
            maxSignatures: expanded.maxSignatures
        };
    }
    var prevOutScript = payments.p2pkh({ pubkey: ourPubKey }).output;
    return {
        prevOutType: SCRIPT_TYPES.P2PKH,
        prevOutScript: prevOutScript,
        hasWitness: false,
        signScript: prevOutScript,
        signType: SCRIPT_TYPES.P2PKH,
        pubkeys: [ourPubKey],
        signatures: [undefined]
    };
}
function build(type, input, allowIncomplete) {
    var pubkeys = (input.pubkeys || []);
    var signatures = (input.signatures || []);
    switch (type) {
        case SCRIPT_TYPES.P2PKH: {
            if (pubkeys.length === 0)
                break;
            if (signatures.length === 0)
                break;
            return payments.p2pkh({ pubkey: pubkeys[0], signature: signatures[0] });
        }
        case SCRIPT_TYPES.P2WPKH: {
            if (pubkeys.length === 0)
                break;
            if (signatures.length === 0)
                break;
            return payments.p2wpkh({ pubkey: pubkeys[0], signature: signatures[0] });
        }
        case SCRIPT_TYPES.P2PK: {
            if (pubkeys.length === 0)
                break;
            if (signatures.length === 0)
                break;
            return payments.p2pk({ signature: signatures[0] });
        }
        case SCRIPT_TYPES.P2MS: {
            var m = input.maxSignatures;
            if (allowIncomplete) {
                signatures = signatures.map(function (x) { return x || script_1.OPS.OP_0; });
            }
            else {
                signatures = signatures.filter(function (x) { return x; });
            }
            // if the transaction is not not complete (complete), or if signatures.length === m, validate
            // otherwise, the number of OP_0's may be >= m, so don't validate (boo)
            var validate = !allowIncomplete || m === signatures.length;
            return payments.p2ms({ m: m, pubkeys: pubkeys, signatures: signatures }, { allowIncomplete: allowIncomplete, validate: validate });
        }
        case SCRIPT_TYPES.HTLC: {
            var redeem = build(input.redeemScriptType, input, allowIncomplete);
            if (!redeem)
                return;
            return payments.htlc({
                redeem: {
                    output: redeem.output || input.redeemScript,
                    input: redeem.input,
                    witness: redeem.witness
                }
            });
        }
        case SCRIPT_TYPES.P2SH: {
            var redeem = build(input.redeemScriptType, input, allowIncomplete);
            if (!redeem)
                return;
            return payments.p2sh({
                redeem: {
                    output: redeem.output || input.redeemScript,
                    input: redeem.input,
                    witness: redeem.witness
                }
            });
        }
        case SCRIPT_TYPES.P2WSH: {
            var redeem = build(input.witnessScriptType, input, allowIncomplete);
            if (!redeem)
                return;
            return payments.p2wsh({
                redeem: {
                    output: input.witnessScript,
                    input: redeem.input,
                    witness: redeem.witness
                }
            });
        }
    }
}
function canSign(input) {
    return (input.signScript !== undefined &&
        input.signType !== undefined &&
        input.pubkeys !== undefined &&
        input.signatures !== undefined &&
        input.signatures.length === input.pubkeys.length &&
        input.pubkeys.length > 0 &&
        (input.hasWitness === false || input.value !== undefined));
}
function signatureHashType(buffer) {
    return buffer.readUInt8(buffer.length - 1);
}
function checkSignArgs(inputs, signParams) {
    if (!PREVOUT_TYPES.has(signParams.prevOutScriptType)) {
        throw new TypeError("Unknown prevOutScriptType \"" + signParams.prevOutScriptType + "\"");
    }
    tfMessage(typeforce.Number, signParams.vin, "sign must include vin parameter as Number (input index)");
    tfMessage(types.Signer, signParams.keyPair, "sign must include keyPair parameter as Signer interface");
    tfMessage(typeforce.maybe(typeforce.Number), signParams.hashType, "sign hashType parameter must be a number");
    var prevOutType = (inputs[signParams.vin] || []).prevOutType;
    var posType = signParams.prevOutScriptType;
    switch (posType) {
        case 'p2pkh':
            if (prevOutType && prevOutType !== 'pubkeyhash') {
                throw new TypeError("input #" + signParams.vin + " is not of type p2pkh: " + prevOutType);
            }
            tfMessage(typeforce.value(undefined), signParams.witnessScript, posType + " requires NO witnessScript");
            tfMessage(typeforce.value(undefined), signParams.redeemScript, posType + " requires NO redeemScript");
            tfMessage(typeforce.value(undefined), signParams.witnessValue, posType + " requires NO witnessValue");
            break;
        case 'p2pk':
            if (prevOutType && prevOutType !== 'pubkey') {
                throw new TypeError("input #" + signParams.vin + " is not of type p2pk: " + prevOutType);
            }
            tfMessage(typeforce.value(undefined), signParams.witnessScript, posType + " requires NO witnessScript");
            tfMessage(typeforce.value(undefined), signParams.redeemScript, posType + " requires NO redeemScript");
            tfMessage(typeforce.value(undefined), signParams.witnessValue, posType + " requires NO witnessValue");
            break;
        case 'p2wpkh':
            if (prevOutType && prevOutType !== 'witnesspubkeyhash') {
                throw new TypeError("input #" + signParams.vin + " is not of type p2wpkh: " + prevOutType);
            }
            tfMessage(typeforce.value(undefined), signParams.witnessScript, posType + " requires NO witnessScript");
            tfMessage(typeforce.value(undefined), signParams.redeemScript, posType + " requires NO redeemScript");
            tfMessage(types.Satoshi, signParams.witnessValue, posType + " requires witnessValue");
            break;
        case 'p2ms':
            if (prevOutType && prevOutType !== 'multisig') {
                throw new TypeError("input #" + signParams.vin + " is not of type p2ms: " + prevOutType);
            }
            tfMessage(typeforce.value(undefined), signParams.witnessScript, posType + " requires NO witnessScript");
            tfMessage(typeforce.value(undefined), signParams.redeemScript, posType + " requires NO redeemScript");
            tfMessage(typeforce.value(undefined), signParams.witnessValue, posType + " requires NO witnessValue");
            break;
        case 'p2sh-p2wpkh':
            if (prevOutType && prevOutType !== 'scripthash') {
                throw new TypeError("input #" + signParams.vin + " is not of type p2sh-p2wpkh: " + prevOutType);
            }
            tfMessage(typeforce.value(undefined), signParams.witnessScript, posType + " requires NO witnessScript");
            tfMessage(typeforce.Buffer, signParams.redeemScript, posType + " requires redeemScript");
            tfMessage(types.Satoshi, signParams.witnessValue, posType + " requires witnessValue");
            break;
        case 'htlc':
            if (prevOutType && prevOutType !== 'htlc') {
                throw new TypeError("input #" + signParams.vin + " is not of type " + posType + ": " + prevOutType);
            }
            /*tfMessage(
              typeforce.string,
              signParams.secret,
              `${posType} requires redeemScript`,
            );*/
            tfMessage(typeforce.Buffer, signParams.redeemScript, posType + " requires redeemScript");
        case 'p2sh-p2ms':
        case 'p2sh-p2pk':
        case 'p2sh-p2pkh':
            if (prevOutType && prevOutType !== 'scripthash') {
                throw new TypeError("input #" + signParams.vin + " is not of type " + posType + ": " + prevOutType);
            }
            tfMessage(typeforce.value(undefined), signParams.witnessScript, posType + " requires NO witnessScript");
            tfMessage(typeforce.Buffer, signParams.redeemScript, posType + " requires redeemScript");
            tfMessage(typeforce.value(undefined), signParams.witnessValue, posType + " requires NO witnessValue");
            break;
        case 'p2wsh-p2ms':
        case 'p2wsh-p2pk':
        case 'p2wsh-p2pkh':
            if (prevOutType && prevOutType !== 'witnessscripthash') {
                throw new TypeError("input #" + signParams.vin + " is not of type " + posType + ": " + prevOutType);
            }
            tfMessage(typeforce.Buffer, signParams.witnessScript, posType + " requires witnessScript");
            tfMessage(typeforce.value(undefined), signParams.redeemScript, posType + " requires NO redeemScript");
            tfMessage(types.Satoshi, signParams.witnessValue, posType + " requires witnessValue");
            break;
        case 'p2sh-p2wsh-p2ms':
        case 'p2sh-p2wsh-p2pk':
        case 'p2sh-p2wsh-p2pkh':
            if (prevOutType && prevOutType !== 'scripthash') {
                throw new TypeError("input #" + signParams.vin + " is not of type " + posType + ": " + prevOutType);
            }
            tfMessage(typeforce.Buffer, signParams.witnessScript, posType + " requires witnessScript");
            tfMessage(typeforce.Buffer, signParams.redeemScript, posType + " requires witnessScript");
            tfMessage(types.Satoshi, signParams.witnessValue, posType + " requires witnessScript");
            break;
    }
}
function trySign(_a) {
    var input = _a.input, ourPubKey = _a.ourPubKey, keyPair = _a.keyPair, signatureHash = _a.signatureHash, hashType = _a.hashType, useLowR = _a.useLowR;
    // enforce in order signing of public keys
    var signed = false;
    for (var _i = 0, _b = input.pubkeys.entries(); _i < _b.length; _i++) {
        var _c = _b[_i], i = _c[0], pubKey = _c[1];
        if (!ourPubKey.equals(pubKey))
            continue;
        if (input.signatures[i])
            throw new Error('Signature already exists');
        // TODO: add tests
        if (ourPubKey.length !== 33 && input.hasWitness) {
            throw new Error('BIP143 rejects uncompressed public keys in P2WPKH or P2WSH');
        }
        var signature = keyPair.sign(signatureHash, useLowR);
        input.signatures[i] = bscript.signature.encode(signature, hashType);
        signed = true; /////////////////////
    }
    if (!signed)
        throw new Error('Key pair cannot sign for this input');
}
function getSigningData(network, inputs, needsOutputs, tx, signParams, keyPair, redeemScript, hashType, witnessValue, witnessScript, useLowR) {
    var vin;
    if (typeof signParams === 'number') {
        console.warn('DEPRECATED: TransactionBuilder sign method arguments ' +
            'will change in v6, please use the TxbSignArg interface');
        vin = signParams;
    }
    else if (typeof signParams === 'object') {
        checkSignArgs(inputs, signParams);
        (vin = signParams.vin, keyPair = signParams.keyPair, redeemScript = signParams.redeemScript, hashType = signParams.hashType, witnessValue = signParams.witnessValue, witnessScript = signParams.witnessScript);
    }
    else {
        throw new TypeError('TransactionBuilder sign first arg must be TxbSignArg or number');
    }
    if (keyPair === undefined) {
        throw new Error('sign requires keypair');
    }
    // TODO: remove keyPair.network matching in 4.0.0
    if (keyPair.network && keyPair.network !== network)
        throw new TypeError('Inconsistent network');
    if (!inputs[vin])
        throw new Error('No input at index: ' + vin);
    hashType = hashType || transaction_1.Transaction.SIGHASH_ALL;
    if (needsOutputs(hashType))
        throw new Error('Transaction needs outputs');
    var input = inputs[vin];
    // if redeemScript was previously provided, enforce consistency
    if (input.redeemScript !== undefined &&
        redeemScript &&
        !input.redeemScript.equals(redeemScript)) {
        throw new Error('Inconsistent redeemScript');
    }
    var ourPubKey = keyPair.publicKey || (keyPair.getPublicKey && keyPair.getPublicKey());
    if (!canSign(input)) {
        if (witnessValue !== undefined) {
            if (input.value !== undefined && input.value !== witnessValue)
                throw new Error('Input did not match witnessValue');
            typeforce(types.Satoshi, witnessValue);
            input.value = witnessValue;
        }
        if (!canSign(input)) {
            var prepared = prepareInput(input, ourPubKey, redeemScript, witnessScript);
            // updates inline
            Object.assign(input, prepared);
        }
        if (!canSign(input))
            throw Error(input.prevOutType + ' not supported');
    }
    // ready to sign
    var signatureHash;
    if (input.hasWitness) {
        signatureHash = tx.hashForWitnessV0(vin, input.signScript, input.value, hashType);
    }
    else {
        signatureHash = tx.hashForSignature(vin, input.signScript, hashType);
    }
    return {
        input: input,
        ourPubKey: ourPubKey,
        keyPair: keyPair,
        signatureHash: signatureHash,
        hashType: hashType,
        useLowR: !!useLowR
    };
}
