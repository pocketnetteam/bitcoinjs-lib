"use strict";
// {signature}
exports.__esModule = true;
var bscript = require("../../script");
function check(script) {
    var chunks = bscript.decompile(script);
    return (chunks.length === 1 &&
        bscript.isCanonicalScriptSignature(chunks[0]));
}
exports.check = check;
check.toJSON = function () {
    return 'pubKey input';
};
