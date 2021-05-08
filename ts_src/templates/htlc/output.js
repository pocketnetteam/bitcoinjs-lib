"use strict";
// OP_HASH160 {scriptHash} OP_EQUAL
exports.__esModule = true;
var bscript = require("../../script");
var script_1 = require("../../script");
function check(script) {
    var buffer = bscript.compile(script);
    return (buffer.length === 92 &&
        buffer[0] === script_1.OPS.OP_IF &&
        buffer[1] === script_1.OPS.OP_SHA256 && buffer[2] === 0x20 && buffer[35] === script_1.OPS.OP_EQUALVERIFY &&
        buffer[36] === script_1.OPS.OP_DUP &&
        buffer[37] === script_1.OPS.OP_HASH160 && buffer[38] === 0x14 &&
        buffer[59] === script_1.OPS.OP_ELSE &&
        buffer[60] === 0x3 &&
        buffer[64] === script_1.OPS.OP_CHECKLOCKTIMEVERIFY &&
        buffer[65] === script_1.OPS.OP_DROP &&
        buffer[66] === script_1.OPS.OP_DUP &&
        buffer[67] === script_1.OPS.OP_HASH160 &&
        buffer[68] === 0x14 &&
        buffer[89] === script_1.OPS.OP_ENDIF &&
        buffer[90] === script_1.OPS.OP_EQUALVERIFY &&
        buffer[91] === script_1.OPS.OP_CHECKSIG);
}
exports.check = check;
check.toJSON = function () {
    return 'htlc output';
};
