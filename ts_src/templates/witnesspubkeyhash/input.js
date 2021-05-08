"use strict";
// {signature} {pubKey}
exports.__esModule = true;
var bscript = require("../../script");
function isCompressedCanonicalPubKey(pubKey) {
    return bscript.isCanonicalPubKey(pubKey) && pubKey.length === 33;
}
function check(script) {
    var chunks = bscript.decompile(script);
    return (chunks.length === 2 &&
        bscript.isCanonicalScriptSignature(chunks[0]) &&
        isCompressedCanonicalPubKey(chunks[1]));
}
exports.check = check;
check.toJSON = function () {
    return 'witnessPubKeyHash input';
};
