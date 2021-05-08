"use strict";
exports.__esModule = true;
var types = require("./types");
var typeforce = require('typeforce');
var varuint = require('varuint-bitcoin');
// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint(value, max) {
    if (typeof value !== 'number')
        throw new Error('cannot write a non-number as a number');
    if (value < 0)
        throw new Error('specified a negative value for writing an unsigned value');
    if (value > max)
        throw new Error('RangeError: value out of range');
    if (Math.floor(value) !== value)
        throw new Error('value has a fractional component');
}
function readUInt64LE(buffer, offset) {
    var a = buffer.readUInt32LE(offset);
    var b = buffer.readUInt32LE(offset + 4);
    b *= 0x100000000;
    verifuint(b + a, 0x001fffffffffffff);
    return b + a;
}
exports.readUInt64LE = readUInt64LE;
function writeUInt64LE(buffer, value, offset) {
    verifuint(value, 0x001fffffffffffff);
    buffer.writeInt32LE(value & -1, offset);
    buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
    return offset + 8;
}
exports.writeUInt64LE = writeUInt64LE;
function reverseBuffer(buffer) {
    if (buffer.length < 1)
        return buffer;
    var j = buffer.length - 1;
    var tmp = 0;
    for (var i = 0; i < buffer.length / 2; i++) {
        tmp = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = tmp;
        j--;
    }
    return buffer;
}
exports.reverseBuffer = reverseBuffer;
function cloneBuffer(buffer) {
    var clone = Buffer.allocUnsafe(buffer.length);
    buffer.copy(clone);
    return clone;
}
exports.cloneBuffer = cloneBuffer;
/**
 * Helper class for serialization of bitcoin data types into a pre-allocated buffer.
 */
var BufferWriter = /** @class */ (function () {
    function BufferWriter(buffer, offset) {
        if (offset === void 0) { offset = 0; }
        this.buffer = buffer;
        this.offset = offset;
        typeforce(types.tuple(types.Buffer, types.UInt32), [buffer, offset]);
    }
    BufferWriter.prototype.writeUInt8 = function (i) {
        this.offset = this.buffer.writeUInt8(i, this.offset);
    };
    BufferWriter.prototype.writeInt32 = function (i) {
        this.offset = this.buffer.writeInt32LE(i, this.offset);
    };
    BufferWriter.prototype.writeUInt32 = function (i) {
        this.offset = this.buffer.writeUInt32LE(i, this.offset);
    };
    BufferWriter.prototype.writeUInt64 = function (i) {
        this.offset = writeUInt64LE(this.buffer, i, this.offset);
    };
    BufferWriter.prototype.writeVarInt = function (i) {
        varuint.encode(i, this.buffer, this.offset);
        this.offset += varuint.encode.bytes;
    };
    BufferWriter.prototype.writeSlice = function (slice) {
        if (this.buffer.length < this.offset + slice.length) {
            throw new Error('Cannot write slice out of bounds');
        }
        this.offset += slice.copy(this.buffer, this.offset);
    };
    BufferWriter.prototype.writeVarSlice = function (slice) {
        this.writeVarInt(slice.length);
        this.writeSlice(slice);
    };
    BufferWriter.prototype.writeVector = function (vector) {
        var _this = this;
        this.writeVarInt(vector.length);
        vector.forEach(function (buf) { return _this.writeVarSlice(buf); });
    };
    return BufferWriter;
}());
exports.BufferWriter = BufferWriter;
/**
 * Helper class for reading of bitcoin data types from a buffer.
 */
var BufferReader = /** @class */ (function () {
    function BufferReader(buffer, offset) {
        if (offset === void 0) { offset = 0; }
        this.buffer = buffer;
        this.offset = offset;
        typeforce(types.tuple(types.Buffer, types.UInt32), [buffer, offset]);
    }
    BufferReader.prototype.readUInt8 = function () {
        var result = this.buffer.readUInt8(this.offset);
        this.offset++;
        return result;
    };
    BufferReader.prototype.readInt32 = function () {
        var result = this.buffer.readInt32LE(this.offset);
        this.offset += 4;
        return result;
    };
    BufferReader.prototype.readUInt32 = function () {
        var result = this.buffer.readUInt32LE(this.offset);
        this.offset += 4;
        return result;
    };
    BufferReader.prototype.readUInt64 = function () {
        var result = readUInt64LE(this.buffer, this.offset);
        this.offset += 8;
        return result;
    };
    BufferReader.prototype.readVarInt = function () {
        var vi = varuint.decode(this.buffer, this.offset);
        this.offset += varuint.decode.bytes;
        return vi;
    };
    BufferReader.prototype.readSlice = function (n) {
        if (this.buffer.length < this.offset + n) {
            throw new Error('Cannot read slice out of bounds');
        }
        var result = this.buffer.slice(this.offset, this.offset + n);
        this.offset += n;
        return result;
    };
    BufferReader.prototype.readVarSlice = function () {
        return this.readSlice(this.readVarInt());
    };
    BufferReader.prototype.readVector = function () {
        var count = this.readVarInt();
        var vector = [];
        for (var i = 0; i < count; i++)
            vector.push(this.readVarSlice());
        return vector;
    };
    return BufferReader;
}());
exports.BufferReader = BufferReader;
