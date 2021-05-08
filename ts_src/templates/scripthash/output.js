"use strict";
// OP_HASH160 {scriptHash} OP_EQUAL
exports.__esModule = true;
var bscript = require("../../script");
var script_1 = require("../../script");
function check(script) {
    var buffer = bscript.compile(script);
    return (buffer.length === 23 &&
        buffer[0] === script_1.OPS.OP_HASH160 &&
        buffer[1] === 0x14 &&
        buffer[22] === script_1.OPS.OP_EQUAL);
}
exports.check = check;
check.toJSON = function () {
    return 'scriptHash output';
};
