"use strict";
// {signature} {pubKey}
exports.__esModule = true;
var bscript = require("../../script");
function check(script) {
    var chunks = bscript.decompile(script);
    return (chunks.length === 2 &&
        bscript.isCanonicalScriptSignature(chunks[0]) &&
        bscript.isCanonicalPubKey(chunks[1]));
}
exports.check = check;
check.toJSON = function () {
    return 'pubKeyHash input';
};
