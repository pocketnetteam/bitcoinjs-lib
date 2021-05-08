"use strict";
exports.__esModule = true;
var networks_1 = require("../networks");
var bscript = require("../script");
var lazy = require("./lazy");
var typef = require('typeforce');
var OPS = bscript.OPS;
function stacksEqual(a, b) {
    if (a.length !== b.length)
        return false;
    return a.every(function (x, i) {
        return x.equals(b[i]);
    });
}
// output: OP_RETURN ...
function p2data(a, opts) {
    if (!a.data && !a.output)
        throw new TypeError('Not enough data');
    opts = Object.assign({ validate: true }, opts || {});
    typef({
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.Buffer),
        data: typef.maybe(typef.arrayOf(typef.Buffer))
    }, a);
    var network = a.network || networks_1.bitcoin;
    var o = { name: 'embed', network: network };
    lazy.prop(o, 'output', function () {
        if (!a.data)
            return;
        return bscript.compile([OPS.OP_RETURN].concat(a.data));
    });
    lazy.prop(o, 'data', function () {
        if (!a.output)
            return;
        return bscript.decompile(a.output).slice(1);
    });
    // extended validation
    if (opts.validate) {
        if (a.output) {
            var chunks = bscript.decompile(a.output);
            if (chunks[0] !== OPS.OP_RETURN)
                throw new TypeError('Output is invalid');
            if (!chunks.slice(1).every(typef.Buffer))
                throw new TypeError('Output is invalid');
            if (a.data && !stacksEqual(a.data, o.data))
                throw new TypeError('Data mismatch');
        }
    }
    return Object.assign(o, a);
}
exports.p2data = p2data;
