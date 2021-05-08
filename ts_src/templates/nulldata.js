"use strict";
exports.__esModule = true;
// OP_RETURN {data}
var bscript = require("../script");
var OPS = bscript.OPS;
function check(script) {
    var buffer = bscript.compile(script);
    return buffer.length > 1 && buffer[0] === OPS.OP_RETURN;
}
exports.check = check;
check.toJSON = function () {
    return 'null data output';
};
var output = { check: check };
exports.output = output;
