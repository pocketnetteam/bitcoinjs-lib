"use strict";
// {pubKey} OP_CHECKSIG
exports.__esModule = true;
var bscript = require("../../script");
var script_1 = require("../../script");
function check(script) {
    var chunks = bscript.decompile(script);
    return (chunks.length === 2 &&
        bscript.isCanonicalPubKey(chunks[0]) &&
        chunks[1] === script_1.OPS.OP_CHECKSIG);
}
exports.check = check;
check.toJSON = function () {
    return 'pubKey output';
};
