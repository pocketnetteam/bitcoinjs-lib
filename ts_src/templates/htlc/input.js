"use strict";
// <scriptSig> {serialized scriptPubKey script}
exports.__esModule = true;
var bscript = require("../../script");
var p2ms = require("../multisig");
var p2pk = require("../pubkey");
var p2pkh = require("../pubkeyhash");
var p2wpkho = require("../witnesspubkeyhash/output");
var p2wsho = require("../witnessscripthash/output");
function check(script, allowIncomplete) {
    var chunks = bscript.decompile(script);
    if (chunks.length < 1)
        return false;
    var lastChunk = chunks[chunks.length - 1];
    if (!Buffer.isBuffer(lastChunk))
        return false;
    var scriptSigChunks = bscript.decompile(bscript.compile(chunks.slice(0, -1)));
    var redeemScriptChunks = bscript.decompile(lastChunk);
    // is redeemScript a valid script?
    if (!redeemScriptChunks)
        return false;
    // is redeemScriptSig push only?
    if (!bscript.isPushOnly(scriptSigChunks))
        return false;
    // is witness?
    if (chunks.length === 1) {
        return (p2wsho.check(redeemScriptChunks) || p2wpkho.check(redeemScriptChunks));
    }
    // match types
    if (p2pkh.input.check(scriptSigChunks) &&
        p2pkh.output.check(redeemScriptChunks))
        return true;
    if (p2ms.input.check(scriptSigChunks, allowIncomplete) &&
        p2ms.output.check(redeemScriptChunks))
        return true;
    if (p2pk.input.check(scriptSigChunks) &&
        p2pk.output.check(redeemScriptChunks))
        return true;
    return false;
}
exports.check = check;
check.toJSON = function () {
    return 'htlc input';
};
