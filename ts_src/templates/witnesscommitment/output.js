"use strict";
// OP_RETURN {aa21a9ed} {commitment}
exports.__esModule = true;
var bscript = require("../../script");
var script_1 = require("../../script");
var types = require("../../types");
var typeforce = require('typeforce');
var HEADER = Buffer.from('aa21a9ed', 'hex');
function check(script) {
    var buffer = bscript.compile(script);
    return (buffer.length > 37 &&
        buffer[0] === script_1.OPS.OP_RETURN &&
        buffer[1] === 0x24 &&
        buffer.slice(2, 6).equals(HEADER));
}
exports.check = check;
check.toJSON = function () {
    return 'Witness commitment output';
};
function encode(commitment) {
    typeforce(types.Hash256bit, commitment);
    var buffer = Buffer.allocUnsafe(36);
    HEADER.copy(buffer, 0);
    commitment.copy(buffer, 4);
    return bscript.compile([script_1.OPS.OP_RETURN, buffer]);
}
exports.encode = encode;
function decode(buffer) {
    typeforce(check, buffer);
    return bscript.decompile(buffer)[1].slice(4, 36);
}
exports.decode = decode;
