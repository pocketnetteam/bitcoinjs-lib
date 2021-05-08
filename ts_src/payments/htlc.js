"use strict";
exports.__esModule = true;
var bcrypto = require("../crypto");
var networks_1 = require("../networks");
var bscript = require("../script");
var address = require("../address");
var lazy = require("./lazy");
var typef = require('typeforce');
var OPS = bscript.OPS;
var bs58check = require('bs58check');
function stacksEqual(a, b) {
    if (a.length !== b.length)
        return false;
    return a.every(function (x, i) {
        return x.equals(b[i]);
    });
}
function clearscript(asm) {
    return asm.replace(/\n\t/g, '').replace(/\s{2,}/g, ' ').replace(/^\s+/, '').replace(/\s+$/, '');
}
// input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL
function htlc(a, opts) {
    if (!a.address && !a.htlc && !a.hash && !a.output && !a.redeem && !a.input)
        throw new TypeError('Not enough data');
    opts = Object.assign({ validate: true }, opts || {});
    typef({
        network: typef.maybe(typef.Object),
        address: typef.maybe(typef.String),
        hash: typef.maybe(typef.BufferN(20)),
        output: typef.maybe(typef.BufferN(23)),
        htlc: typef.maybe(typef.Object),
        redeem: typef.maybe({
            network: typef.maybe(typef.Object),
            output: typef.maybe(typef.Buffer),
            input: typef.maybe(typef.Buffer),
            witness: typef.maybe(typef.arrayOf(typef.Buffer))
        }),
        input: typef.maybe(typef.Buffer),
        witness: typef.maybe(typef.arrayOf(typef.Buffer))
    }, a);
    var network = a.network;
    if (!network) {
        network = (a.redeem && a.redeem.network) || networks_1.bitcoin;
    }
    var o = { network: network };
    var _address = lazy.value(function () {
        var payload = bs58check.decode(a.address);
        var version = payload.readUInt8(0);
        var hash = payload.slice(1);
        return { version: version, hash: hash };
    });
    var _chunks = lazy.value(function () {
        return bscript.decompile(a.input);
    });
    var _redeem = lazy.value(function () {
        var chunks = _chunks();
        return {
            network: network,
            output: chunks[chunks.length - 1],
            input: bscript.compile(chunks.slice(0, -1)),
            witness: a.witness || []
        };
    });
    // output dependents
    lazy.prop(o, 'address', function () {
        if (!o.hash)
            return;
        var payload = Buffer.allocUnsafe(21);
        payload.writeUInt8(o.network.scriptHash, 0);
        o.hash.copy(payload, 1);
        return bs58check.encode(payload);
    });
    lazy.prop(o, 'htlc', function () {
        return a.htlc;
    });
    lazy.prop(o, 'hash', function () {
        // in order of least effort
        if (a.output)
            return a.output.slice(2, 22);
        if (a.address)
            return _address().hash;
        if (o.redeem && o.redeem.output)
            return bcrypto.hash160(o.redeem.output);
    });
    lazy.prop(o, 'output', function () {
        if (!o.htlc)
            return;
        var senderhash = address.fromBase58Check(o.htlc.sender).hash;
        var recieverhash = address.fromBase58Check(o.htlc.reciever).hash;
        var lockbuf = bscript.number.encode(o.htlc.lock);
        var hash = o.htlc.secret ? bcrypto.sha256(Buffer.from(o.htlc.secret)).toString('hex') : o.htlc.secrethash;
        var asm2 = clearscript("\n        OP_IF\n            OP_SHA256 " + hash + " OP_EQUALVERIFY\n            OP_DUP \n            OP_HASH160 " + recieverhash.toString('hex') + "\n        OP_ELSE\n            " + lockbuf.toString('hex') + " OP_CHECKLOCKTIMEVERIFY \n            OP_DROP \n            OP_DUP \n            OP_HASH160 " + senderhash.toString('hex') + "\n        OP_ENDIF\n        OP_EQUALVERIFY\n        OP_CHECKSIG\n    ");
        return bscript.fromASM(asm2);
    });
    // input dependents
    lazy.prop(o, 'redeem', function () {
        if (!a.input)
            return;
        return _redeem();
    });
    lazy.prop(o, 'input', function () {
        if (!a.redeem || !a.redeem.input || !a.redeem.output)
            return;
        return bscript.compile([].concat(bscript.decompile(a.redeem.input), a.redeem.output));
    });
    lazy.prop(o, 'witness', function () {
        if (o.redeem && o.redeem.witness)
            return o.redeem.witness;
        if (o.input)
            return [];
    });
    lazy.prop(o, 'name', function () {
        var nameParts = ['htlc'];
        if (o.redeem !== undefined && o.redeem.name !== undefined)
            nameParts.push(o.redeem.name);
        return nameParts.join('-');
    });
    if (opts.validate) {
        var hash_1 = Buffer.from([]);
        if (a.address) {
            if (_address().version !== network.scriptHash)
                throw new TypeError('Invalid version or Network mismatch');
            if (_address().hash.length !== 20)
                throw new TypeError('Invalid address');
            hash_1 = _address().hash;
        }
        if (a.hash) {
            if (hash_1.length > 0 && !hash_1.equals(a.hash))
                throw new TypeError('Hash mismatch');
            else
                hash_1 = a.hash;
        }
        if (a.output) {
            var valid = (a.output.length === 92 &&
                a.output[0] === OPS.OP_IF &&
                a.output[1] === OPS.OP_SHA256 && a.output[2] === 0x20 && a.output[35] === OPS.OP_EQUALVERIFY &&
                a.output[36] === OPS.OP_DUP &&
                a.output[37] === OPS.OP_HASH160 && a.output[38] === 0x14 &&
                a.output[59] === OPS.OP_ELSE &&
                a.output[60] === 0x3 &&
                a.output[64] === OPS.OP_CHECKLOCKTIMEVERIFY &&
                a.output[65] === OPS.OP_DROP &&
                a.output[66] === OPS.OP_DUP &&
                a.output[67] === OPS.OP_HASH160 &&
                a.output[68] === 0x14 &&
                a.output[89] === OPS.OP_ENDIF &&
                a.output[90] === OPS.OP_EQUALVERIFY &&
                a.output[91] === OPS.OP_CHECKSIG);
            if (!valid)
                throw new TypeError('Output is invalid');
            var hash2 = a.output.slice(0, 92);
            if (hash_1.length > 0 && !hash_1.equals(hash2))
                throw new TypeError('Hash mismatch');
            else
                hash_1 = hash2;
        }
        // inlined to prevent 'no-inner-declarations' failing
        var checkRedeem = function (redeem) {
            // is the redeem output empty/invalid?
            if (redeem.output) {
                var decompile = bscript.decompile(redeem.output);
                if (!decompile || decompile.length < 1)
                    throw new TypeError('Redeem.output too short');
                // match hash against other sources
                var hash2 = bcrypto.hash160(redeem.output);
                if (hash_1.length > 0 && !hash_1.equals(hash2))
                    throw new TypeError('Hash mismatch');
                else
                    hash_1 = hash2;
            }
            if (redeem.input) {
                var hasInput = redeem.input.length > 0;
                var hasWitness = redeem.witness && redeem.witness.length > 0;
                if (!hasInput && !hasWitness)
                    throw new TypeError('Empty input');
                if (hasInput && hasWitness)
                    throw new TypeError('Input and witness provided');
                if (hasInput) {
                    var richunks = bscript.decompile(redeem.input);
                    if (!bscript.isPushOnly(richunks))
                        throw new TypeError('Non push-only scriptSig');
                }
            }
        };
        if (a.input) {
            var chunks = _chunks();
            if (!chunks || chunks.length < 1)
                throw new TypeError('Input too short');
            if (!Buffer.isBuffer(_redeem().output))
                throw new TypeError('Input is invalid');
            checkRedeem(_redeem());
        }
        if (a.redeem) {
            if (a.redeem.network && a.redeem.network !== network)
                throw new TypeError('Network mismatch');
            if (a.input) {
                var redeem = _redeem();
                if (a.redeem.output && !a.redeem.output.equals(redeem.output))
                    throw new TypeError('Redeem.output mismatch');
                if (a.redeem.input && !a.redeem.input.equals(redeem.input))
                    throw new TypeError('Redeem.input mismatch');
            }
            checkRedeem(a.redeem);
        }
        if (a.witness) {
            if (a.redeem &&
                a.redeem.witness &&
                !stacksEqual(a.redeem.witness, a.witness))
                throw new TypeError('Witness and redeem.witness mismatch');
        }
    }
    return Object.assign(o, a);
}
exports.htlc = htlc;
