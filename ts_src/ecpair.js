"use strict";
exports.__esModule = true;
var NETWORKS = require("./networks");
var types = require("./types");
var ecc = require('tiny-secp256k1');
var randomBytes = require('randombytes');
var typeforce = require('typeforce');
var wif = require('wif');
var isOptions = typeforce.maybe(typeforce.compile({
    compressed: types.maybe(types.Boolean),
    network: types.maybe(types.Network)
}));
var ECPair = /** @class */ (function () {
    function ECPair(__D, __Q, options) {
        this.__D = __D;
        this.__Q = __Q;
        this.lowR = false;
        if (options === undefined)
            options = {};
        this.compressed =
            options.compressed === undefined ? true : options.compressed;
        this.network = options.network || NETWORKS.bitcoin;
        if (__Q !== undefined)
            this.__Q = ecc.pointCompress(__Q, this.compressed);
    }
    Object.defineProperty(ECPair.prototype, "privateKey", {
        get: function () {
            return this.__D;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ECPair.prototype, "publicKey", {
        get: function () {
            if (!this.__Q)
                this.__Q = ecc.pointFromScalar(this.__D, this.compressed);
            return this.__Q;
        },
        enumerable: true,
        configurable: true
    });
    ECPair.prototype.toWIF = function () {
        if (!this.__D)
            throw new Error('Missing private key');
        return wif.encode(this.network.wif, this.__D, this.compressed);
    };
    ECPair.prototype.sign = function (hash, lowR) {
        if (!this.__D)
            throw new Error('Missing private key');
        if (lowR === undefined)
            lowR = this.lowR;
        if (lowR === false) {
            return ecc.sign(hash, this.__D);
        }
        else {
            var sig = ecc.sign(hash, this.__D);
            var extraData = Buffer.alloc(32, 0);
            var counter = 0;
            // if first try is lowR, skip the loop
            // for second try and on, add extra entropy counting up
            while (sig[0] > 0x7f) {
                counter++;
                extraData.writeUIntLE(counter, 0, 6);
                sig = ecc.signWithEntropy(hash, this.__D, extraData);
            }
            return sig;
        }
    };
    ECPair.prototype.verify = function (hash, signature) {
        return ecc.verify(hash, this.publicKey, signature);
    };
    return ECPair;
}());
function fromPrivateKey(buffer, options) {
    typeforce(types.Buffer256bit, buffer);
    if (!ecc.isPrivate(buffer))
        throw new TypeError('Private key not in range [1, n)');
    typeforce(isOptions, options);
    return new ECPair(buffer, undefined, options);
}
exports.fromPrivateKey = fromPrivateKey;
function fromPublicKey(buffer, options) {
    typeforce(ecc.isPoint, buffer);
    typeforce(isOptions, options);
    return new ECPair(undefined, buffer, options);
}
exports.fromPublicKey = fromPublicKey;
function fromWIF(wifString, network) {
    var decoded = wif.decode(wifString);
    var version = decoded.version;
    // list of networks?
    if (types.Array(network)) {
        network = network
            .filter(function (x) {
            return version === x.wif;
        })
            .pop();
        if (!network)
            throw new Error('Unknown network version');
        // otherwise, assume a network object (or default to bitcoin)
    }
    else {
        network = network || NETWORKS.bitcoin;
        if (version !== network.wif)
            throw new Error('Invalid network version');
    }
    return fromPrivateKey(decoded.privateKey, {
        compressed: decoded.compressed,
        network: network
    });
}
exports.fromWIF = fromWIF;
function makeRandom(options) {
    typeforce(isOptions, options);
    if (options === undefined)
        options = {};
    var rng = options.rng || randomBytes;
    var d;
    do {
        d = rng(32);
        typeforce(types.Buffer256bit, d);
    } while (!ecc.isPrivate(d));
    return fromPrivateKey(d, options);
}
exports.makeRandom = makeRandom;
