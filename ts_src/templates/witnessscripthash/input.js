"use strict";
// <scriptSig> {serialized scriptPubKey script}
exports.__esModule = true;
var bscript = require("../../script");
var typeforce = require('typeforce');
var p2ms = require("../multisig");
var p2pk = require("../pubkey");
var p2pkh = require("../pubkeyhash");
function check(chunks, allowIncomplete) {
    typeforce(typeforce.Array, chunks);
    if (chunks.length < 1)
        return false;
    var witnessScript = chunks[chunks.length - 1];
    if (!Buffer.isBuffer(witnessScript))
        return false;
    var witnessScriptChunks = bscript.decompile(witnessScript);
    // is witnessScript a valid script?
    if (!witnessScriptChunks || witnessScriptChunks.length === 0)
        return false;
    var witnessRawScriptSig = bscript.compile(chunks.slice(0, -1));
    // match types
    if (p2pkh.input.check(witnessRawScriptSig) &&
        p2pkh.output.check(witnessScriptChunks))
        return true;
    if (p2ms.input.check(witnessRawScriptSig, allowIncomplete) &&
        p2ms.output.check(witnessScriptChunks))
        return true;
    if (p2pk.input.check(witnessRawScriptSig) &&
        p2pk.output.check(witnessScriptChunks))
        return true;
    return false;
}
exports.check = check;
check.toJSON = function () {
    return 'witnessScriptHash input';
};
