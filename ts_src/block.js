"use strict";
exports.__esModule = true;
var bufferutils_1 = require("./bufferutils");
var bcrypto = require("./crypto");
var transaction_1 = require("./transaction");
var types = require("./types");
var fastMerkleRoot = require('merkle-lib/fastRoot');
var typeforce = require('typeforce');
var varuint = require('varuint-bitcoin');
var errorMerkleNoTxes = new TypeError('Cannot compute merkle root for zero transactions');
var errorWitnessNotSegwit = new TypeError('Cannot compute witness commit for non-segwit block');
var Block = /** @class */ (function () {
    function Block() {
        this.version = 1;
        this.prevHash = undefined;
        this.merkleRoot = undefined;
        this.timestamp = 0;
        this.witnessCommit = undefined;
        this.bits = 0;
        this.nonce = 0;
        this.transactions = undefined;
    }
    Block.fromBuffer = function (buffer) {
        if (buffer.length < 80)
            throw new Error('Buffer too small (< 80 bytes)');
        var bufferReader = new bufferutils_1.BufferReader(buffer);
        var block = new Block();
        block.version = bufferReader.readInt32();
        block.prevHash = bufferReader.readSlice(32);
        block.merkleRoot = bufferReader.readSlice(32);
        block.timestamp = bufferReader.readUInt32();
        block.bits = bufferReader.readUInt32();
        block.nonce = bufferReader.readUInt32();
        if (buffer.length === 80)
            return block;
        var readTransaction = function () {
            var tx = transaction_1.Transaction.fromBuffer(bufferReader.buffer.slice(bufferReader.offset), true);
            bufferReader.offset += tx.byteLength();
            return tx;
        };
        var nTransactions = bufferReader.readVarInt();
        block.transactions = [];
        for (var i = 0; i < nTransactions; ++i) {
            var tx = readTransaction();
            block.transactions.push(tx);
        }
        var witnessCommit = block.getWitnessCommit();
        // This Block contains a witness commit
        if (witnessCommit)
            block.witnessCommit = witnessCommit;
        return block;
    };
    Block.fromHex = function (hex) {
        return Block.fromBuffer(Buffer.from(hex, 'hex'));
    };
    Block.calculateTarget = function (bits) {
        var exponent = ((bits & 0xff000000) >> 24) - 3;
        var mantissa = bits & 0x007fffff;
        var target = Buffer.alloc(32, 0);
        target.writeUIntBE(mantissa, 29 - exponent, 3);
        return target;
    };
    Block.calculateMerkleRoot = function (transactions, forWitness) {
        typeforce([{ getHash: types.Function }], transactions);
        if (transactions.length === 0)
            throw errorMerkleNoTxes;
        if (forWitness && !txesHaveWitnessCommit(transactions))
            throw errorWitnessNotSegwit;
        var hashes = transactions.map(function (transaction) {
            return transaction.getHash(forWitness);
        });
        var rootHash = fastMerkleRoot(hashes, bcrypto.hash256);
        return forWitness
            ? bcrypto.hash256(Buffer.concat([rootHash, transactions[0].ins[0].witness[0]]))
            : rootHash;
    };
    Block.prototype.getWitnessCommit = function () {
        if (!txesHaveWitnessCommit(this.transactions))
            return null;
        // The merkle root for the witness data is in an OP_RETURN output.
        // There is no rule for the index of the output, so use filter to find it.
        // The root is prepended with 0xaa21a9ed so check for 0x6a24aa21a9ed
        // If multiple commits are found, the output with highest index is assumed.
        var witnessCommits = this.transactions[0].outs.filter(function (out) {
            return out.script.slice(0, 6).equals(Buffer.from('6a24aa21a9ed', 'hex'));
        }).map(function (out) { return out.script.slice(6, 38); });
        if (witnessCommits.length === 0)
            return null;
        // Use the commit with the highest output (should only be one though)
        var result = witnessCommits[witnessCommits.length - 1];
        if (!(result instanceof Buffer && result.length === 32))
            return null;
        return result;
    };
    Block.prototype.hasWitnessCommit = function () {
        if (this.witnessCommit instanceof Buffer &&
            this.witnessCommit.length === 32)
            return true;
        if (this.getWitnessCommit() !== null)
            return true;
        return false;
    };
    Block.prototype.hasWitness = function () {
        return anyTxHasWitness(this.transactions);
    };
    Block.prototype.weight = function () {
        var base = this.byteLength(false, false);
        var total = this.byteLength(false, true);
        return base * 3 + total;
    };
    Block.prototype.byteLength = function (headersOnly, allowWitness) {
        if (allowWitness === void 0) { allowWitness = true; }
        if (headersOnly || !this.transactions)
            return 80;
        return (80 +
            varuint.encodingLength(this.transactions.length) +
            this.transactions.reduce(function (a, x) { return a + x.byteLength(allowWitness); }, 0));
    };
    Block.prototype.getHash = function () {
        return bcrypto.hash256(this.toBuffer(true));
    };
    Block.prototype.getId = function () {
        return bufferutils_1.reverseBuffer(this.getHash()).toString('hex');
    };
    Block.prototype.getUTCDate = function () {
        var date = new Date(0); // epoch
        date.setUTCSeconds(this.timestamp);
        return date;
    };
    // TODO: buffer, offset compatibility
    Block.prototype.toBuffer = function (headersOnly) {
        var buffer = Buffer.allocUnsafe(this.byteLength(headersOnly));
        var bufferWriter = new bufferutils_1.BufferWriter(buffer);
        bufferWriter.writeInt32(this.version);
        bufferWriter.writeSlice(this.prevHash);
        bufferWriter.writeSlice(this.merkleRoot);
        bufferWriter.writeUInt32(this.timestamp);
        bufferWriter.writeUInt32(this.bits);
        bufferWriter.writeUInt32(this.nonce);
        if (headersOnly || !this.transactions)
            return buffer;
        varuint.encode(this.transactions.length, buffer, bufferWriter.offset);
        bufferWriter.offset += varuint.encode.bytes;
        this.transactions.forEach(function (tx) {
            var txSize = tx.byteLength(); // TODO: extract from toBuffer?
            tx.toBuffer(buffer, bufferWriter.offset);
            bufferWriter.offset += txSize;
        });
        return buffer;
    };
    Block.prototype.toHex = function (headersOnly) {
        return this.toBuffer(headersOnly).toString('hex');
    };
    Block.prototype.checkTxRoots = function () {
        // If the Block has segwit transactions but no witness commit,
        // there's no way it can be valid, so fail the check.
        var hasWitnessCommit = this.hasWitnessCommit();
        if (!hasWitnessCommit && this.hasWitness())
            return false;
        return (this.__checkMerkleRoot() &&
            (hasWitnessCommit ? this.__checkWitnessCommit() : true));
    };
    Block.prototype.checkProofOfWork = function () {
        var hash = bufferutils_1.reverseBuffer(this.getHash());
        var target = Block.calculateTarget(this.bits);
        return hash.compare(target) <= 0;
    };
    Block.prototype.__checkMerkleRoot = function () {
        if (!this.transactions)
            throw errorMerkleNoTxes;
        var actualMerkleRoot = Block.calculateMerkleRoot(this.transactions);
        return this.merkleRoot.compare(actualMerkleRoot) === 0;
    };
    Block.prototype.__checkWitnessCommit = function () {
        if (!this.transactions)
            throw errorMerkleNoTxes;
        if (!this.hasWitnessCommit())
            throw errorWitnessNotSegwit;
        var actualWitnessCommit = Block.calculateMerkleRoot(this.transactions, true);
        return this.witnessCommit.compare(actualWitnessCommit) === 0;
    };
    return Block;
}());
exports.Block = Block;
function txesHaveWitnessCommit(transactions) {
    return (transactions instanceof Array &&
        transactions[0] &&
        transactions[0].ins &&
        transactions[0].ins instanceof Array &&
        transactions[0].ins[0] &&
        transactions[0].ins[0].witness &&
        transactions[0].ins[0].witness instanceof Array &&
        transactions[0].ins[0].witness.length > 0);
}
function anyTxHasWitness(transactions) {
    return (transactions instanceof Array &&
        transactions.some(function (tx) {
            return typeof tx === 'object' &&
                tx.ins instanceof Array &&
                tx.ins.some(function (input) {
                    return typeof input === 'object' &&
                        input.witness instanceof Array &&
                        input.witness.length > 0;
                });
        }));
}
