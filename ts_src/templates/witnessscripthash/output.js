"use strict";
// OP_0 {scriptHash}
exports.__esModule = true;
var bscript = require("../../script");
var script_1 = require("../../script");
function check(script) {
    var buffer = bscript.compile(script);
    return buffer.length === 34 && buffer[0] === script_1.OPS.OP_0 && buffer[1] === 0x20;
}
exports.check = check;
check.toJSON = function () {
    return 'Witness scriptHash output';
};
