"use strict";
// OP_DUP OP_HASH160 {pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG
exports.__esModule = true;
var bscript = require("../../script");
var script_1 = require("../../script");
function check(script) {
    var buffer = bscript.compile(script);
    return (buffer.length === 25 &&
        buffer[0] === script_1.OPS.OP_DUP &&
        buffer[1] === script_1.OPS.OP_HASH160 &&
        buffer[2] === 0x14 &&
        buffer[23] === script_1.OPS.OP_EQUALVERIFY &&
        buffer[24] === script_1.OPS.OP_CHECKSIG);
}
exports.check = check;
check.toJSON = function () {
    return 'pubKeyHash output';
};
