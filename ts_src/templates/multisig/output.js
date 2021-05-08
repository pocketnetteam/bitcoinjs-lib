"use strict";
// m [pubKeys ...] n OP_CHECKMULTISIG
exports.__esModule = true;
var bscript = require("../../script");
var script_1 = require("../../script");
var types = require("../../types");
var OP_INT_BASE = script_1.OPS.OP_RESERVED; // OP_1 - 1
function check(script, allowIncomplete) {
    var chunks = bscript.decompile(script);
    if (chunks.length < 4)
        return false;
    if (chunks[chunks.length - 1] !== script_1.OPS.OP_CHECKMULTISIG)
        return false;
    if (!types.Number(chunks[0]))
        return false;
    if (!types.Number(chunks[chunks.length - 2]))
        return false;
    var m = chunks[0] - OP_INT_BASE;
    var n = chunks[chunks.length - 2] - OP_INT_BASE;
    if (m <= 0)
        return false;
    if (n > 16)
        return false;
    if (m > n)
        return false;
    if (n !== chunks.length - 3)
        return false;
    if (allowIncomplete)
        return true;
    var keys = chunks.slice(1, -2);
    return keys.every(bscript.isCanonicalPubKey);
}
exports.check = check;
check.toJSON = function () {
    return 'multi-sig output';
};
