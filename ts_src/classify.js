"use strict";
exports.__esModule = true;
var script_1 = require("./script");
var multisig = require("./templates/multisig");
var nullData = require("./templates/nulldata");
var pubKey = require("./templates/pubkey");
var pubKeyHash = require("./templates/pubkeyhash");
var scriptHash = require("./templates/scripthash");
var htlc = require("./templates/htlc");
var witnessCommitment = require("./templates/witnesscommitment");
var witnessPubKeyHash = require("./templates/witnesspubkeyhash");
var witnessScriptHash = require("./templates/witnessscripthash");
var types = {
    P2MS: 'multisig',
    NONSTANDARD: 'nonstandard',
    NULLDATA: 'nulldata',
    P2PK: 'pubkey',
    P2PKH: 'pubkeyhash',
    HTLC: 'htlc',
    P2SH: 'scripthash',
    P2WPKH: 'witnesspubkeyhash',
    P2WSH: 'witnessscripthash',
    WITNESS_COMMITMENT: 'witnesscommitment'
};
exports.types = types;
function classifyOutput(script) {
    if (witnessPubKeyHash.output.check(script))
        return types.P2WPKH;
    if (witnessScriptHash.output.check(script))
        return types.P2WSH;
    if (pubKeyHash.output.check(script))
        return types.P2PKH;
    if (scriptHash.output.check(script))
        return types.P2SH;
    if (htlc.output.check(script))
        return types.HTLC;
    // XXX: optimization, below functions .decompile before use
    var chunks = script_1.decompile(script);
    if (!chunks)
        throw new TypeError('Invalid script');
    if (multisig.output.check(chunks))
        return types.P2MS;
    if (pubKey.output.check(chunks))
        return types.P2PK;
    if (witnessCommitment.output.check(chunks))
        return types.WITNESS_COMMITMENT;
    if (nullData.output.check(chunks))
        return types.NULLDATA;
    return types.NONSTANDARD;
}
exports.output = classifyOutput;
function classifyInput(script, allowIncomplete) {
    // XXX: optimization, below functions .decompile before use
    var chunks = script_1.decompile(script);
    if (!chunks)
        throw new TypeError('Invalid script');
    if (pubKeyHash.input.check(chunks))
        return types.P2PKH;
    if (scriptHash.input.check(chunks, allowIncomplete))
        return types.P2SH;
    if (htlc.input.check(chunks, allowIncomplete))
        return types.HTLC;
    if (multisig.input.check(chunks, allowIncomplete))
        return types.P2MS;
    if (pubKey.input.check(chunks))
        return types.P2PK;
    return types.NONSTANDARD;
}
exports.input = classifyInput;
function classifyWitness(script, allowIncomplete) {
    // XXX: optimization, below functions .decompile before use
    var chunks = script_1.decompile(script);
    if (!chunks)
        throw new TypeError('Invalid script');
    if (witnessPubKeyHash.input.check(chunks))
        return types.P2WPKH;
    if (witnessScriptHash.input.check(chunks, allowIncomplete))
        return types.P2WSH;
    return types.NONSTANDARD;
}
exports.witness = classifyWitness;
