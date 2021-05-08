"use strict";
exports.__esModule = true;
var bip174_1 = require("bip174");
var varuint = require("bip174/src/lib/converter/varint");
var utils_1 = require("bip174/src/lib/utils");
var address_1 = require("./address");
var bufferutils_1 = require("./bufferutils");
var crypto_1 = require("./crypto");
var ecpair_1 = require("./ecpair");
var networks_1 = require("./networks");
var payments = require("./payments");
var bscript = require("./script");
var transaction_1 = require("./transaction");
/**
 * These are the default arguments for a Psbt instance.
 */
var DEFAULT_OPTS = {
    /**
     * A bitcoinjs Network object. This is only used if you pass an `address`
     * parameter to addOutput. Otherwise it is not needed and can be left default.
     */
    network: networks_1.bitcoin,
    /**
     * When extractTransaction is called, the fee rate is checked.
     * THIS IS NOT TO BE RELIED ON.
     * It is only here as a last ditch effort to prevent sending a 500 BTC fee etc.
     */
    maximumFeeRate: 5000
};
/**
 * Psbt class can parse and generate a PSBT binary based off of the BIP174.
 * There are 6 roles that this class fulfills. (Explained in BIP174)
 *
 * Creator: This can be done with `new Psbt()`
 * Updater: This can be done with `psbt.addInput(input)`, `psbt.addInputs(inputs)`,
 *   `psbt.addOutput(output)`, `psbt.addOutputs(outputs)` when you are looking to
 *   add new inputs and outputs to the PSBT, and `psbt.updateGlobal(itemObject)`,
 *   `psbt.updateInput(itemObject)`, `psbt.updateOutput(itemObject)`
 *   addInput requires hash: Buffer | string; and index: number; as attributes
 *   and can also include any attributes that are used in updateInput method.
 *   addOutput requires script: Buffer; and value: number; and likewise can include
 *   data for updateOutput.
 *   For a list of what attributes should be what types. Check the bip174 library.
 *   Also, check the integration tests for some examples of usage.
 * Signer: There are a few methods. signAllInputs and signAllInputsAsync, which will search all input
 *   information for your pubkey or pubkeyhash, and only sign inputs where it finds
 *   your info. Or you can explicitly sign a specific input with signInput and
 *   signInputAsync. For the async methods you can create a SignerAsync object
 *   and use something like a hardware wallet to sign with. (You must implement this)
 * Combiner: psbts can be combined easily with `psbt.combine(psbt2, psbt3, psbt4 ...)`
 *   the psbt calling combine will always have precedence when a conflict occurs.
 *   Combine checks if the internal bitcoin transaction is the same, so be sure that
 *   all sequences, version, locktime, etc. are the same before combining.
 * Input Finalizer: This role is fairly important. Not only does it need to construct
 *   the input scriptSigs and witnesses, but it SHOULD verify the signatures etc.
 *   Before running `psbt.finalizeAllInputs()` please run `psbt.validateSignaturesOfAllInputs()`
 *   Running any finalize method will delete any data in the input(s) that are no longer
 *   needed due to the finalized scripts containing the information.
 * Transaction Extractor: This role will perform some checks before returning a
 *   Transaction object. Such as fee rate not being larger than maximumFeeRate etc.
 */
var Psbt = /** @class */ (function () {
    function Psbt(opts, data) {
        if (opts === void 0) { opts = {}; }
        if (data === void 0) { data = new bip174_1.Psbt(new PsbtTransaction()); }
        this.data = data;
        // set defaults
        this.opts = Object.assign({}, DEFAULT_OPTS, opts);
        this.__CACHE = {
            __NON_WITNESS_UTXO_TX_CACHE: [],
            __NON_WITNESS_UTXO_BUF_CACHE: [],
            __TX_IN_CACHE: {},
            __TX: this.data.globalMap.unsignedTx.tx,
            // Old TransactionBuilder behavior was to not confirm input values
            // before signing. Even though we highly encourage people to get
            // the full parent transaction to verify values, the ability to
            // sign non-segwit inputs without the full transaction was often
            // requested. So the only way to activate is to use @ts-ignore.
            // We will disable exporting the Psbt when unsafe sign is active.
            // because it is not BIP174 compliant.
            __UNSAFE_SIGN_NONSEGWIT: false
        };
        if (this.data.inputs.length === 0)
            this.setVersion(2);
        // Make data hidden when enumerating
        var dpew = function (obj, attr, enumerable, writable) {
            return Object.defineProperty(obj, attr, {
                enumerable: enumerable,
                writable: writable
            });
        };
        dpew(this, '__CACHE', false, true);
        dpew(this, 'opts', false, true);
    }
    Psbt.fromBase64 = function (data, opts) {
        if (opts === void 0) { opts = {}; }
        var buffer = Buffer.from(data, 'base64');
        return this.fromBuffer(buffer, opts);
    };
    Psbt.fromHex = function (data, opts) {
        if (opts === void 0) { opts = {}; }
        var buffer = Buffer.from(data, 'hex');
        return this.fromBuffer(buffer, opts);
    };
    Psbt.fromBuffer = function (buffer, opts) {
        if (opts === void 0) { opts = {}; }
        var psbtBase = bip174_1.Psbt.fromBuffer(buffer, transactionFromBuffer);
        var psbt = new Psbt(opts, psbtBase);
        checkTxForDupeIns(psbt.__CACHE.__TX, psbt.__CACHE);
        return psbt;
    };
    Object.defineProperty(Psbt.prototype, "inputCount", {
        get: function () {
            return this.data.inputs.length;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Psbt.prototype, "version", {
        get: function () {
            return this.__CACHE.__TX.version;
        },
        set: function (version) {
            this.setVersion(version);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Psbt.prototype, "locktime", {
        get: function () {
            return this.__CACHE.__TX.locktime;
        },
        set: function (locktime) {
            this.setLocktime(locktime);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Psbt.prototype, "txInputs", {
        get: function () {
            return this.__CACHE.__TX.ins.map(function (input) { return ({
                hash: bufferutils_1.cloneBuffer(input.hash),
                index: input.index,
                sequence: input.sequence
            }); });
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Psbt.prototype, "txOutputs", {
        get: function () {
            var _this = this;
            return this.__CACHE.__TX.outs.map(function (output) {
                var address;
                try {
                    address = address_1.fromOutputScript(output.script, _this.opts.network);
                }
                catch (_) { }
                return {
                    script: bufferutils_1.cloneBuffer(output.script),
                    value: output.value,
                    address: address
                };
            });
        },
        enumerable: true,
        configurable: true
    });
    Psbt.prototype.combine = function () {
        var those = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            those[_i] = arguments[_i];
        }
        var _a;
        (_a = this.data).combine.apply(_a, those.map(function (o) { return o.data; }));
        return this;
    };
    Psbt.prototype.clone = function () {
        // TODO: more efficient cloning
        var res = Psbt.fromBuffer(this.data.toBuffer());
        res.opts = JSON.parse(JSON.stringify(this.opts));
        return res;
    };
    Psbt.prototype.setMaximumFeeRate = function (satoshiPerByte) {
        check32Bit(satoshiPerByte); // 42.9 BTC per byte IS excessive... so throw
        this.opts.maximumFeeRate = satoshiPerByte;
    };
    Psbt.prototype.setVersion = function (version) {
        check32Bit(version);
        checkInputsForPartialSig(this.data.inputs, 'setVersion');
        var c = this.__CACHE;
        c.__TX.version = version;
        c.__EXTRACTED_TX = undefined;
        return this;
    };
    Psbt.prototype.setLocktime = function (locktime) {
        check32Bit(locktime);
        checkInputsForPartialSig(this.data.inputs, 'setLocktime');
        var c = this.__CACHE;
        c.__TX.locktime = locktime;
        c.__EXTRACTED_TX = undefined;
        return this;
    };
    Psbt.prototype.setInputSequence = function (inputIndex, sequence) {
        check32Bit(sequence);
        checkInputsForPartialSig(this.data.inputs, 'setInputSequence');
        var c = this.__CACHE;
        if (c.__TX.ins.length <= inputIndex) {
            throw new Error('Input index too high');
        }
        c.__TX.ins[inputIndex].sequence = sequence;
        c.__EXTRACTED_TX = undefined;
        return this;
    };
    Psbt.prototype.addInputs = function (inputDatas) {
        var _this = this;
        inputDatas.forEach(function (inputData) { return _this.addInput(inputData); });
        return this;
    };
    Psbt.prototype.addInput = function (inputData) {
        if (arguments.length > 1 ||
            !inputData ||
            inputData.hash === undefined ||
            inputData.index === undefined) {
            throw new Error("Invalid arguments for Psbt.addInput. " +
                "Requires single object with at least [hash] and [index]");
        }
        checkInputsForPartialSig(this.data.inputs, 'addInput');
        if (inputData.witnessScript)
            checkInvalidP2WSH(inputData.witnessScript);
        var c = this.__CACHE;
        this.data.addInput(inputData);
        var txIn = c.__TX.ins[c.__TX.ins.length - 1];
        checkTxInputCache(c, txIn);
        var inputIndex = this.data.inputs.length - 1;
        var input = this.data.inputs[inputIndex];
        if (input.nonWitnessUtxo) {
            addNonWitnessTxCache(this.__CACHE, input, inputIndex);
        }
        c.__FEE = undefined;
        c.__FEE_RATE = undefined;
        c.__EXTRACTED_TX = undefined;
        return this;
    };
    Psbt.prototype.addOutputs = function (outputDatas) {
        var _this = this;
        outputDatas.forEach(function (outputData) { return _this.addOutput(outputData); });
        return this;
    };
    Psbt.prototype.addOutput = function (outputData) {
        if (arguments.length > 1 ||
            !outputData ||
            outputData.value === undefined ||
            (outputData.address === undefined &&
                outputData.script === undefined)) {
            throw new Error("Invalid arguments for Psbt.addOutput. " +
                "Requires single object with at least [script or address] and [value]");
        }
        checkInputsForPartialSig(this.data.inputs, 'addOutput');
        var address = outputData.address;
        if (typeof address === 'string') {
            var network = this.opts.network;
            var script = address_1.toOutputScript(address, network);
            outputData = Object.assign(outputData, { script: script });
        }
        var c = this.__CACHE;
        this.data.addOutput(outputData);
        c.__FEE = undefined;
        c.__FEE_RATE = undefined;
        c.__EXTRACTED_TX = undefined;
        return this;
    };
    Psbt.prototype.extractTransaction = function (disableFeeCheck) {
        if (!this.data.inputs.every(isFinalized))
            throw new Error('Not finalized');
        var c = this.__CACHE;
        if (!disableFeeCheck) {
            checkFees(this, c, this.opts);
        }
        if (c.__EXTRACTED_TX)
            return c.__EXTRACTED_TX;
        var tx = c.__TX.clone();
        inputFinalizeGetAmts(this.data.inputs, tx, c, true);
        return tx;
    };
    Psbt.prototype.getFeeRate = function () {
        return getTxCacheValue('__FEE_RATE', 'fee rate', this.data.inputs, this.__CACHE);
    };
    Psbt.prototype.getFee = function () {
        return getTxCacheValue('__FEE', 'fee', this.data.inputs, this.__CACHE);
    };
    Psbt.prototype.finalizeAllInputs = function () {
        var _this = this;
        utils_1.checkForInput(this.data.inputs, 0); // making sure we have at least one
        range(this.data.inputs.length).forEach(function (idx) { return _this.finalizeInput(idx); });
        return this;
    };
    Psbt.prototype.finalizeInput = function (inputIndex, finalScriptsFunc) {
        if (finalScriptsFunc === void 0) { finalScriptsFunc = getFinalScripts; }
        var input = utils_1.checkForInput(this.data.inputs, inputIndex);
        var _a = getScriptFromInput(inputIndex, input, this.__CACHE), script = _a.script, isP2SH = _a.isP2SH, isP2WSH = _a.isP2WSH, isSegwit = _a.isSegwit;
        if (!script)
            throw new Error("No script found for input #" + inputIndex);
        checkPartialSigSighashes(input);
        var _b = finalScriptsFunc(inputIndex, input, script, isSegwit, isP2SH, isP2WSH), finalScriptSig = _b.finalScriptSig, finalScriptWitness = _b.finalScriptWitness;
        if (finalScriptSig)
            this.data.updateInput(inputIndex, { finalScriptSig: finalScriptSig });
        if (finalScriptWitness)
            this.data.updateInput(inputIndex, { finalScriptWitness: finalScriptWitness });
        if (!finalScriptSig && !finalScriptWitness)
            throw new Error("Unknown error finalizing input #" + inputIndex);
        this.data.clearFinalizedInput(inputIndex);
        return this;
    };
    Psbt.prototype.getInputType = function (inputIndex) {
        var input = utils_1.checkForInput(this.data.inputs, inputIndex);
        var script = getScriptFromUtxo(inputIndex, input, this.__CACHE);
        var result = getMeaningfulScript(script, inputIndex, 'input', input.redeemScript || redeemFromFinalScriptSig(input.finalScriptSig), input.witnessScript ||
            redeemFromFinalWitnessScript(input.finalScriptWitness));
        var type = result.type === 'raw' ? '' : result.type + '-';
        var mainType = classifyScript(result.meaningfulScript);
        return (type + mainType);
    };
    Psbt.prototype.inputHasPubkey = function (inputIndex, pubkey) {
        var input = utils_1.checkForInput(this.data.inputs, inputIndex);
        return pubkeyInInput(pubkey, input, inputIndex, this.__CACHE);
    };
    Psbt.prototype.inputHasHDKey = function (inputIndex, root) {
        var input = utils_1.checkForInput(this.data.inputs, inputIndex);
        var derivationIsMine = bip32DerivationIsMine(root);
        return (!!input.bip32Derivation && input.bip32Derivation.some(derivationIsMine));
    };
    Psbt.prototype.outputHasPubkey = function (outputIndex, pubkey) {
        var output = utils_1.checkForOutput(this.data.outputs, outputIndex);
        return pubkeyInOutput(pubkey, output, outputIndex, this.__CACHE);
    };
    Psbt.prototype.outputHasHDKey = function (outputIndex, root) {
        var output = utils_1.checkForOutput(this.data.outputs, outputIndex);
        var derivationIsMine = bip32DerivationIsMine(root);
        return (!!output.bip32Derivation && output.bip32Derivation.some(derivationIsMine));
    };
    Psbt.prototype.validateSignaturesOfAllInputs = function () {
        var _this = this;
        utils_1.checkForInput(this.data.inputs, 0); // making sure we have at least one
        var results = range(this.data.inputs.length).map(function (idx) {
            return _this.validateSignaturesOfInput(idx);
        });
        return results.reduce(function (final, res) { return res === true && final; }, true);
    };
    Psbt.prototype.validateSignaturesOfInput = function (inputIndex, pubkey) {
        var input = this.data.inputs[inputIndex];
        var partialSig = (input || {}).partialSig;
        if (!input || !partialSig || partialSig.length < 1)
            throw new Error('No signatures to validate');
        var mySigs = pubkey
            ? partialSig.filter(function (sig) { return sig.pubkey.equals(pubkey); })
            : partialSig;
        if (mySigs.length < 1)
            throw new Error('No signatures for this pubkey');
        var results = [];
        var hashCache;
        var scriptCache;
        var sighashCache;
        for (var _i = 0, mySigs_1 = mySigs; _i < mySigs_1.length; _i++) {
            var pSig = mySigs_1[_i];
            var sig = bscript.signature.decode(pSig.signature);
            var _a = sighashCache !== sig.hashType
                ? getHashForSig(inputIndex, Object.assign({}, input, { sighashType: sig.hashType }), this.__CACHE, true)
                : { hash: hashCache, script: scriptCache }, hash = _a.hash, script = _a.script;
            sighashCache = sig.hashType;
            hashCache = hash;
            scriptCache = script;
            checkScriptForPubkey(pSig.pubkey, script, 'verify');
            var keypair = ecpair_1.fromPublicKey(pSig.pubkey);
            results.push(keypair.verify(hash, sig.signature));
        }
        return results.every(function (res) { return res === true; });
    };
    Psbt.prototype.signAllInputsHD = function (hdKeyPair, sighashTypes) {
        if (sighashTypes === void 0) { sighashTypes = [transaction_1.Transaction.SIGHASH_ALL]; }
        if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
            throw new Error('Need HDSigner to sign input');
        }
        var results = [];
        for (var _i = 0, _a = range(this.data.inputs.length); _i < _a.length; _i++) {
            var i = _a[_i];
            try {
                this.signInputHD(i, hdKeyPair, sighashTypes);
                results.push(true);
            }
            catch (err) {
                results.push(false);
            }
        }
        if (results.every(function (v) { return v === false; })) {
            throw new Error('No inputs were signed');
        }
        return this;
    };
    Psbt.prototype.signAllInputsHDAsync = function (hdKeyPair, sighashTypes) {
        var _this = this;
        if (sighashTypes === void 0) { sighashTypes = [transaction_1.Transaction.SIGHASH_ALL]; }
        return new Promise(function (resolve, reject) {
            if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
                return reject(new Error('Need HDSigner to sign input'));
            }
            var results = [];
            var promises = [];
            for (var _i = 0, _a = range(_this.data.inputs.length); _i < _a.length; _i++) {
                var i = _a[_i];
                promises.push(_this.signInputHDAsync(i, hdKeyPair, sighashTypes).then(function () {
                    results.push(true);
                }, function () {
                    results.push(false);
                }));
            }
            return Promise.all(promises).then(function () {
                if (results.every(function (v) { return v === false; })) {
                    return reject(new Error('No inputs were signed'));
                }
                resolve();
            });
        });
    };
    Psbt.prototype.signInputHD = function (inputIndex, hdKeyPair, sighashTypes) {
        var _this = this;
        if (sighashTypes === void 0) { sighashTypes = [transaction_1.Transaction.SIGHASH_ALL]; }
        if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
            throw new Error('Need HDSigner to sign input');
        }
        var signers = getSignersFromHD(inputIndex, this.data.inputs, hdKeyPair);
        signers.forEach(function (signer) { return _this.signInput(inputIndex, signer, sighashTypes); });
        return this;
    };
    Psbt.prototype.signInputHDAsync = function (inputIndex, hdKeyPair, sighashTypes) {
        var _this = this;
        if (sighashTypes === void 0) { sighashTypes = [transaction_1.Transaction.SIGHASH_ALL]; }
        return new Promise(function (resolve, reject) {
            if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
                return reject(new Error('Need HDSigner to sign input'));
            }
            var signers = getSignersFromHD(inputIndex, _this.data.inputs, hdKeyPair);
            var promises = signers.map(function (signer) {
                return _this.signInputAsync(inputIndex, signer, sighashTypes);
            });
            return Promise.all(promises)
                .then(function () {
                resolve();
            })["catch"](reject);
        });
    };
    Psbt.prototype.signAllInputs = function (keyPair, sighashTypes) {
        if (sighashTypes === void 0) { sighashTypes = [transaction_1.Transaction.SIGHASH_ALL]; }
        if (!keyPair || !keyPair.publicKey)
            throw new Error('Need Signer to sign input');
        // TODO: Add a pubkey/pubkeyhash cache to each input
        // as input information is added, then eventually
        // optimize this method.
        var results = [];
        for (var _i = 0, _a = range(this.data.inputs.length); _i < _a.length; _i++) {
            var i = _a[_i];
            try {
                this.signInput(i, keyPair, sighashTypes);
                results.push(true);
            }
            catch (err) {
                results.push(false);
            }
        }
        if (results.every(function (v) { return v === false; })) {
            throw new Error('No inputs were signed');
        }
        return this;
    };
    Psbt.prototype.signAllInputsAsync = function (keyPair, sighashTypes) {
        var _this = this;
        if (sighashTypes === void 0) { sighashTypes = [transaction_1.Transaction.SIGHASH_ALL]; }
        return new Promise(function (resolve, reject) {
            if (!keyPair || !keyPair.publicKey)
                return reject(new Error('Need Signer to sign input'));
            // TODO: Add a pubkey/pubkeyhash cache to each input
            // as input information is added, then eventually
            // optimize this method.
            var results = [];
            var promises = [];
            for (var _i = 0, _a = _this.data.inputs.entries(); _i < _a.length; _i++) {
                var i = _a[_i][0];
                promises.push(_this.signInputAsync(i, keyPair, sighashTypes).then(function () {
                    results.push(true);
                }, function () {
                    results.push(false);
                }));
            }
            return Promise.all(promises).then(function () {
                if (results.every(function (v) { return v === false; })) {
                    return reject(new Error('No inputs were signed'));
                }
                resolve();
            });
        });
    };
    Psbt.prototype.signInput = function (inputIndex, keyPair, sighashTypes) {
        if (sighashTypes === void 0) { sighashTypes = [transaction_1.Transaction.SIGHASH_ALL]; }
        if (!keyPair || !keyPair.publicKey)
            throw new Error('Need Signer to sign input');
        var _a = getHashAndSighashType(this.data.inputs, inputIndex, keyPair.publicKey, this.__CACHE, sighashTypes), hash = _a.hash, sighashType = _a.sighashType;
        var partialSig = [
            {
                pubkey: keyPair.publicKey,
                signature: bscript.signature.encode(keyPair.sign(hash), sighashType)
            },
        ];
        this.data.updateInput(inputIndex, { partialSig: partialSig });
        return this;
    };
    Psbt.prototype.signInputAsync = function (inputIndex, keyPair, sighashTypes) {
        var _this = this;
        if (sighashTypes === void 0) { sighashTypes = [transaction_1.Transaction.SIGHASH_ALL]; }
        return Promise.resolve().then(function () {
            if (!keyPair || !keyPair.publicKey)
                throw new Error('Need Signer to sign input');
            var _a = getHashAndSighashType(_this.data.inputs, inputIndex, keyPair.publicKey, _this.__CACHE, sighashTypes), hash = _a.hash, sighashType = _a.sighashType;
            return Promise.resolve(keyPair.sign(hash)).then(function (signature) {
                var partialSig = [
                    {
                        pubkey: keyPair.publicKey,
                        signature: bscript.signature.encode(signature, sighashType)
                    },
                ];
                _this.data.updateInput(inputIndex, { partialSig: partialSig });
            });
        });
    };
    Psbt.prototype.toBuffer = function () {
        checkCache(this.__CACHE);
        return this.data.toBuffer();
    };
    Psbt.prototype.toHex = function () {
        checkCache(this.__CACHE);
        return this.data.toHex();
    };
    Psbt.prototype.toBase64 = function () {
        checkCache(this.__CACHE);
        return this.data.toBase64();
    };
    Psbt.prototype.updateGlobal = function (updateData) {
        this.data.updateGlobal(updateData);
        return this;
    };
    Psbt.prototype.updateInput = function (inputIndex, updateData) {
        if (updateData.witnessScript)
            checkInvalidP2WSH(updateData.witnessScript);
        this.data.updateInput(inputIndex, updateData);
        if (updateData.nonWitnessUtxo) {
            addNonWitnessTxCache(this.__CACHE, this.data.inputs[inputIndex], inputIndex);
        }
        return this;
    };
    Psbt.prototype.updateOutput = function (outputIndex, updateData) {
        this.data.updateOutput(outputIndex, updateData);
        return this;
    };
    Psbt.prototype.addUnknownKeyValToGlobal = function (keyVal) {
        this.data.addUnknownKeyValToGlobal(keyVal);
        return this;
    };
    Psbt.prototype.addUnknownKeyValToInput = function (inputIndex, keyVal) {
        this.data.addUnknownKeyValToInput(inputIndex, keyVal);
        return this;
    };
    Psbt.prototype.addUnknownKeyValToOutput = function (outputIndex, keyVal) {
        this.data.addUnknownKeyValToOutput(outputIndex, keyVal);
        return this;
    };
    Psbt.prototype.clearFinalizedInput = function (inputIndex) {
        this.data.clearFinalizedInput(inputIndex);
        return this;
    };
    return Psbt;
}());
exports.Psbt = Psbt;
/**
 * This function is needed to pass to the bip174 base class's fromBuffer.
 * It takes the "transaction buffer" portion of the psbt buffer and returns a
 * Transaction (From the bip174 library) interface.
 */
var transactionFromBuffer = function (buffer) { return new PsbtTransaction(buffer); };
/**
 * This class implements the Transaction interface from bip174 library.
 * It contains a bitcoinjs-lib Transaction object.
 */
var PsbtTransaction = /** @class */ (function () {
    function PsbtTransaction(buffer) {
        if (buffer === void 0) { buffer = Buffer.from([2, 0, 0, 0, 0, 0, 0, 0, 0, 0]); }
        this.tx = transaction_1.Transaction.fromBuffer(buffer);
        checkTxEmpty(this.tx);
        Object.defineProperty(this, 'tx', {
            enumerable: false,
            writable: true
        });
    }
    PsbtTransaction.prototype.getInputOutputCounts = function () {
        return {
            inputCount: this.tx.ins.length,
            outputCount: this.tx.outs.length
        };
    };
    PsbtTransaction.prototype.addInput = function (input) {
        if (input.hash === undefined ||
            input.index === undefined ||
            (!Buffer.isBuffer(input.hash) &&
                typeof input.hash !== 'string') ||
            typeof input.index !== 'number') {
            throw new Error('Error adding input.');
        }
        var hash = typeof input.hash === 'string'
            ? bufferutils_1.reverseBuffer(Buffer.from(input.hash, 'hex'))
            : input.hash;
        this.tx.addInput(hash, input.index, input.sequence);
    };
    PsbtTransaction.prototype.addOutput = function (output) {
        if (output.script === undefined ||
            output.value === undefined ||
            !Buffer.isBuffer(output.script) ||
            typeof output.value !== 'number') {
            throw new Error('Error adding output.');
        }
        this.tx.addOutput(output.script, output.value);
    };
    PsbtTransaction.prototype.toBuffer = function () {
        return this.tx.toBuffer();
    };
    return PsbtTransaction;
}());
function canFinalize(input, script, scriptType) {
    switch (scriptType) {
        case 'pubkey':
        case 'pubkeyhash':
        case 'witnesspubkeyhash':
            return hasSigs(1, input.partialSig);
        case 'multisig':
            var p2ms = payments.p2ms({ output: script });
            return hasSigs(p2ms.m, input.partialSig, p2ms.pubkeys);
        default:
            return false;
    }
}
function checkCache(cache) {
    if (cache.__UNSAFE_SIGN_NONSEGWIT !== false) {
        throw new Error('Not BIP174 compliant, can not export');
    }
}
function hasSigs(neededSigs, partialSig, pubkeys) {
    if (!partialSig)
        return false;
    var sigs;
    if (pubkeys) {
        sigs = pubkeys
            .map(function (pkey) {
            var pubkey = ecpair_1.fromPublicKey(pkey, { compressed: true })
                .publicKey;
            return partialSig.find(function (pSig) { return pSig.pubkey.equals(pubkey); });
        })
            .filter(function (v) { return !!v; });
    }
    else {
        sigs = partialSig;
    }
    if (sigs.length > neededSigs)
        throw new Error('Too many signatures');
    return sigs.length === neededSigs;
}
function isFinalized(input) {
    return !!input.finalScriptSig || !!input.finalScriptWitness;
}
function isPaymentFactory(payment) {
    return function (script) {
        try {
            payment({ output: script });
            return true;
        }
        catch (err) {
            return false;
        }
    };
}
var isP2MS = isPaymentFactory(payments.p2ms);
var isP2PK = isPaymentFactory(payments.p2pk);
var isP2PKH = isPaymentFactory(payments.p2pkh);
var isP2WPKH = isPaymentFactory(payments.p2wpkh);
var isP2WSHScript = isPaymentFactory(payments.p2wsh);
var isP2SHScript = isPaymentFactory(payments.p2sh);
function bip32DerivationIsMine(root) {
    return function (d) {
        if (!d.masterFingerprint.equals(root.fingerprint))
            return false;
        if (!root.derivePath(d.path).publicKey.equals(d.pubkey))
            return false;
        return true;
    };
}
function check32Bit(num) {
    if (typeof num !== 'number' ||
        num !== Math.floor(num) ||
        num > 0xffffffff ||
        num < 0) {
        throw new Error('Invalid 32 bit integer');
    }
}
function checkFees(psbt, cache, opts) {
    var feeRate = cache.__FEE_RATE || psbt.getFeeRate();
    var vsize = cache.__EXTRACTED_TX.virtualSize();
    var satoshis = feeRate * vsize;
    if (feeRate >= opts.maximumFeeRate) {
        throw new Error("Warning: You are paying around " + (satoshis / 1e8).toFixed(8) + " in " +
            ("fees, which is " + feeRate + " satoshi per byte for a transaction ") +
            ("with a VSize of " + vsize + " bytes (segwit counted as 0.25 byte per ") +
            "byte). Use setMaximumFeeRate method to raise your threshold, or " +
            "pass true to the first arg of extractTransaction.");
    }
}
function checkInputsForPartialSig(inputs, action) {
    inputs.forEach(function (input) {
        var throws = false;
        var pSigs = [];
        if ((input.partialSig || []).length === 0) {
            if (!input.finalScriptSig && !input.finalScriptWitness)
                return;
            pSigs = getPsigsFromInputFinalScripts(input);
        }
        else {
            pSigs = input.partialSig;
        }
        pSigs.forEach(function (pSig) {
            var hashType = bscript.signature.decode(pSig.signature).hashType;
            var whitelist = [];
            var isAnyoneCanPay = hashType & transaction_1.Transaction.SIGHASH_ANYONECANPAY;
            if (isAnyoneCanPay)
                whitelist.push('addInput');
            var hashMod = hashType & 0x1f;
            switch (hashMod) {
                case transaction_1.Transaction.SIGHASH_ALL:
                    break;
                case transaction_1.Transaction.SIGHASH_SINGLE:
                case transaction_1.Transaction.SIGHASH_NONE:
                    whitelist.push('addOutput');
                    whitelist.push('setInputSequence');
                    break;
            }
            if (whitelist.indexOf(action) === -1) {
                throws = true;
            }
        });
        if (throws) {
            throw new Error('Can not modify transaction, signatures exist.');
        }
    });
}
function checkPartialSigSighashes(input) {
    if (!input.sighashType || !input.partialSig)
        return;
    var partialSig = input.partialSig, sighashType = input.sighashType;
    partialSig.forEach(function (pSig) {
        var hashType = bscript.signature.decode(pSig.signature).hashType;
        if (sighashType !== hashType) {
            throw new Error('Signature sighash does not match input sighash type');
        }
    });
}
function checkScriptForPubkey(pubkey, script, action) {
    if (!pubkeyInScript(pubkey, script)) {
        throw new Error("Can not " + action + " for this input with the key " + pubkey.toString('hex'));
    }
}
function checkTxEmpty(tx) {
    var isEmpty = tx.ins.every(function (input) {
        return input.script &&
            input.script.length === 0 &&
            input.witness &&
            input.witness.length === 0;
    });
    if (!isEmpty) {
        throw new Error('Format Error: Transaction ScriptSigs are not empty');
    }
}
function checkTxForDupeIns(tx, cache) {
    tx.ins.forEach(function (input) {
        checkTxInputCache(cache, input);
    });
}
function checkTxInputCache(cache, input) {
    var key = bufferutils_1.reverseBuffer(Buffer.from(input.hash)).toString('hex') + ':' + input.index;
    if (cache.__TX_IN_CACHE[key])
        throw new Error('Duplicate input detected.');
    cache.__TX_IN_CACHE[key] = 1;
}
function scriptCheckerFactory(payment, paymentScriptName) {
    return function (inputIndex, scriptPubKey, redeemScript, ioType) {
        var redeemScriptOutput = payment({
            redeem: { output: redeemScript }
        }).output;
        if (!scriptPubKey.equals(redeemScriptOutput)) {
            throw new Error(paymentScriptName + " for " + ioType + " #" + inputIndex + " doesn't match the scriptPubKey in the prevout");
        }
    };
}
var checkRedeemScript = scriptCheckerFactory(payments.p2sh, 'Redeem script');
var checkWitnessScript = scriptCheckerFactory(payments.p2wsh, 'Witness script');
function getTxCacheValue(key, name, inputs, c) {
    if (!inputs.every(isFinalized))
        throw new Error("PSBT must be finalized to calculate " + name);
    if (key === '__FEE_RATE' && c.__FEE_RATE)
        return c.__FEE_RATE;
    if (key === '__FEE' && c.__FEE)
        return c.__FEE;
    var tx;
    var mustFinalize = true;
    if (c.__EXTRACTED_TX) {
        tx = c.__EXTRACTED_TX;
        mustFinalize = false;
    }
    else {
        tx = c.__TX.clone();
    }
    inputFinalizeGetAmts(inputs, tx, c, mustFinalize);
    if (key === '__FEE_RATE')
        return c.__FEE_RATE;
    else if (key === '__FEE')
        return c.__FEE;
}
function getFinalScripts(inputIndex, input, script, isSegwit, isP2SH, isP2WSH) {
    var scriptType = classifyScript(script);
    if (!canFinalize(input, script, scriptType))
        throw new Error("Can not finalize input #" + inputIndex);
    return prepareFinalScripts(script, scriptType, input.partialSig, isSegwit, isP2SH, isP2WSH);
}
function prepareFinalScripts(script, scriptType, partialSig, isSegwit, isP2SH, isP2WSH) {
    var finalScriptSig;
    var finalScriptWitness;
    // Wow, the payments API is very handy
    var payment = getPayment(script, scriptType, partialSig);
    var p2wsh = !isP2WSH ? null : payments.p2wsh({ redeem: payment });
    var p2sh = !isP2SH ? null : payments.p2sh({ redeem: p2wsh || payment });
    if (isSegwit) {
        if (p2wsh) {
            finalScriptWitness = witnessStackToScriptWitness(p2wsh.witness);
        }
        else {
            finalScriptWitness = witnessStackToScriptWitness(payment.witness);
        }
        if (p2sh) {
            finalScriptSig = p2sh.input;
        }
    }
    else {
        if (p2sh) {
            finalScriptSig = p2sh.input;
        }
        else {
            finalScriptSig = payment.input;
        }
    }
    return {
        finalScriptSig: finalScriptSig,
        finalScriptWitness: finalScriptWitness
    };
}
function getHashAndSighashType(inputs, inputIndex, pubkey, cache, sighashTypes) {
    var input = utils_1.checkForInput(inputs, inputIndex);
    var _a = getHashForSig(inputIndex, input, cache, false, sighashTypes), hash = _a.hash, sighashType = _a.sighashType, script = _a.script;
    checkScriptForPubkey(pubkey, script, 'sign');
    return {
        hash: hash,
        sighashType: sighashType
    };
}
function getHashForSig(inputIndex, input, cache, forValidate, sighashTypes) {
    var unsignedTx = cache.__TX;
    var sighashType = input.sighashType || transaction_1.Transaction.SIGHASH_ALL;
    if (sighashTypes && sighashTypes.indexOf(sighashType) < 0) {
        var str = sighashTypeToString(sighashType);
        throw new Error("Sighash type is not allowed. Retry the sign method passing the " +
            ("sighashTypes array of whitelisted types. Sighash type: " + str));
    }
    var hash;
    var prevout;
    if (input.nonWitnessUtxo) {
        var nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(cache, input, inputIndex);
        var prevoutHash = unsignedTx.ins[inputIndex].hash;
        var utxoHash = nonWitnessUtxoTx.getHash();
        // If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
        if (!prevoutHash.equals(utxoHash)) {
            throw new Error("Non-witness UTXO hash for input #" + inputIndex + " doesn't match the hash specified in the prevout");
        }
        var prevoutIndex = unsignedTx.ins[inputIndex].index;
        prevout = nonWitnessUtxoTx.outs[prevoutIndex];
    }
    else if (input.witnessUtxo) {
        prevout = input.witnessUtxo;
    }
    else {
        throw new Error('Need a Utxo input item for signing');
    }
    var _a = getMeaningfulScript(prevout.script, inputIndex, 'input', input.redeemScript, input.witnessScript), meaningfulScript = _a.meaningfulScript, type = _a.type;
    if (['p2sh-p2wsh', 'p2wsh'].indexOf(type) >= 0) {
        hash = unsignedTx.hashForWitnessV0(inputIndex, meaningfulScript, prevout.value, sighashType);
    }
    else if (isP2WPKH(meaningfulScript)) {
        // P2WPKH uses the P2PKH template for prevoutScript when signing
        var signingScript = payments.p2pkh({ hash: meaningfulScript.slice(2) })
            .output;
        hash = unsignedTx.hashForWitnessV0(inputIndex, signingScript, prevout.value, sighashType);
    }
    else {
        // non-segwit
        if (input.nonWitnessUtxo === undefined &&
            cache.__UNSAFE_SIGN_NONSEGWIT === false)
            throw new Error("Input #" + inputIndex + " has witnessUtxo but non-segwit script: " +
                ("" + meaningfulScript.toString('hex')));
        if (!forValidate && cache.__UNSAFE_SIGN_NONSEGWIT !== false)
            console.warn('Warning: Signing non-segwit inputs without the full parent transaction ' +
                'means there is a chance that a miner could feed you incorrect information ' +
                'to trick you into paying large fees. This behavior is the same as the old ' +
                'TransactionBuilder class when signing non-segwit scripts. You are not ' +
                'able to export this Psbt with toBuffer|toBase64|toHex since it is not ' +
                'BIP174 compliant.\n*********************\nPROCEED WITH CAUTION!\n' +
                '*********************');
        hash = unsignedTx.hashForSignature(inputIndex, meaningfulScript, sighashType);
    }
    return {
        script: meaningfulScript,
        sighashType: sighashType,
        hash: hash
    };
}
function getPayment(script, scriptType, partialSig) {
    var payment;
    switch (scriptType) {
        case 'multisig':
            var sigs = getSortedSigs(script, partialSig);
            payment = payments.p2ms({
                output: script,
                signatures: sigs
            });
            break;
        case 'pubkey':
            payment = payments.p2pk({
                output: script,
                signature: partialSig[0].signature
            });
            break;
        case 'pubkeyhash':
            payment = payments.p2pkh({
                output: script,
                pubkey: partialSig[0].pubkey,
                signature: partialSig[0].signature
            });
            break;
        case 'witnesspubkeyhash':
            payment = payments.p2wpkh({
                output: script,
                pubkey: partialSig[0].pubkey,
                signature: partialSig[0].signature
            });
            break;
    }
    return payment;
}
function getPsigsFromInputFinalScripts(input) {
    var scriptItems = !input.finalScriptSig
        ? []
        : bscript.decompile(input.finalScriptSig) || [];
    var witnessItems = !input.finalScriptWitness
        ? []
        : bscript.decompile(input.finalScriptWitness) || [];
    return scriptItems
        .concat(witnessItems)
        .filter(function (item) {
        return Buffer.isBuffer(item) && bscript.isCanonicalScriptSignature(item);
    })
        .map(function (sig) { return ({ signature: sig }); });
}
function getScriptFromInput(inputIndex, input, cache) {
    var unsignedTx = cache.__TX;
    var res = {
        script: null,
        isSegwit: false,
        isP2SH: false,
        isP2WSH: false
    };
    res.isP2SH = !!input.redeemScript;
    res.isP2WSH = !!input.witnessScript;
    if (input.witnessScript) {
        res.script = input.witnessScript;
    }
    else if (input.redeemScript) {
        res.script = input.redeemScript;
    }
    else {
        if (input.nonWitnessUtxo) {
            var nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(cache, input, inputIndex);
            var prevoutIndex = unsignedTx.ins[inputIndex].index;
            res.script = nonWitnessUtxoTx.outs[prevoutIndex].script;
        }
        else if (input.witnessUtxo) {
            res.script = input.witnessUtxo.script;
        }
    }
    if (input.witnessScript || isP2WPKH(res.script)) {
        res.isSegwit = true;
    }
    return res;
}
function getSignersFromHD(inputIndex, inputs, hdKeyPair) {
    var input = utils_1.checkForInput(inputs, inputIndex);
    if (!input.bip32Derivation || input.bip32Derivation.length === 0) {
        throw new Error('Need bip32Derivation to sign with HD');
    }
    var myDerivations = input.bip32Derivation
        .map(function (bipDv) {
        if (bipDv.masterFingerprint.equals(hdKeyPair.fingerprint)) {
            return bipDv;
        }
        else {
            return;
        }
    })
        .filter(function (v) { return !!v; });
    if (myDerivations.length === 0) {
        throw new Error('Need one bip32Derivation masterFingerprint to match the HDSigner fingerprint');
    }
    var signers = myDerivations.map(function (bipDv) {
        var node = hdKeyPair.derivePath(bipDv.path);
        if (!bipDv.pubkey.equals(node.publicKey)) {
            throw new Error('pubkey did not match bip32Derivation');
        }
        return node;
    });
    return signers;
}
function getSortedSigs(script, partialSig) {
    var p2ms = payments.p2ms({ output: script });
    // for each pubkey in order of p2ms script
    return p2ms
        .pubkeys.map(function (pk) {
        // filter partialSig array by pubkey being equal
        return (partialSig.filter(function (ps) {
            return ps.pubkey.equals(pk);
        })[0] || {}).signature;
        // Any pubkey without a match will return undefined
        // this last filter removes all the undefined items in the array.
    })
        .filter(function (v) { return !!v; });
}
function scriptWitnessToWitnessStack(buffer) {
    var offset = 0;
    function readSlice(n) {
        offset += n;
        return buffer.slice(offset - n, offset);
    }
    function readVarInt() {
        var vi = varuint.decode(buffer, offset);
        offset += varuint.decode.bytes;
        return vi;
    }
    function readVarSlice() {
        return readSlice(readVarInt());
    }
    function readVector() {
        var count = readVarInt();
        var vector = [];
        for (var i = 0; i < count; i++)
            vector.push(readVarSlice());
        return vector;
    }
    return readVector();
}
function sighashTypeToString(sighashType) {
    var text = sighashType & transaction_1.Transaction.SIGHASH_ANYONECANPAY
        ? 'SIGHASH_ANYONECANPAY | '
        : '';
    var sigMod = sighashType & 0x1f;
    switch (sigMod) {
        case transaction_1.Transaction.SIGHASH_ALL:
            text += 'SIGHASH_ALL';
            break;
        case transaction_1.Transaction.SIGHASH_SINGLE:
            text += 'SIGHASH_SINGLE';
            break;
        case transaction_1.Transaction.SIGHASH_NONE:
            text += 'SIGHASH_NONE';
            break;
    }
    return text;
}
function witnessStackToScriptWitness(witness) {
    var buffer = Buffer.allocUnsafe(0);
    function writeSlice(slice) {
        buffer = Buffer.concat([buffer, Buffer.from(slice)]);
    }
    function writeVarInt(i) {
        var currentLen = buffer.length;
        var varintLen = varuint.encodingLength(i);
        buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)]);
        varuint.encode(i, buffer, currentLen);
    }
    function writeVarSlice(slice) {
        writeVarInt(slice.length);
        writeSlice(slice);
    }
    function writeVector(vector) {
        writeVarInt(vector.length);
        vector.forEach(writeVarSlice);
    }
    writeVector(witness);
    return buffer;
}
function addNonWitnessTxCache(cache, input, inputIndex) {
    cache.__NON_WITNESS_UTXO_BUF_CACHE[inputIndex] = input.nonWitnessUtxo;
    var tx = transaction_1.Transaction.fromBuffer(input.nonWitnessUtxo);
    cache.__NON_WITNESS_UTXO_TX_CACHE[inputIndex] = tx;
    var self = cache;
    var selfIndex = inputIndex;
    delete input.nonWitnessUtxo;
    Object.defineProperty(input, 'nonWitnessUtxo', {
        enumerable: true,
        get: function () {
            var buf = self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex];
            var txCache = self.__NON_WITNESS_UTXO_TX_CACHE[selfIndex];
            if (buf !== undefined) {
                return buf;
            }
            else {
                var newBuf = txCache.toBuffer();
                self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = newBuf;
                return newBuf;
            }
        },
        set: function (data) {
            self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = data;
        }
    });
}
function inputFinalizeGetAmts(inputs, tx, cache, mustFinalize) {
    var inputAmount = 0;
    inputs.forEach(function (input, idx) {
        if (mustFinalize && input.finalScriptSig)
            tx.ins[idx].script = input.finalScriptSig;
        if (mustFinalize && input.finalScriptWitness) {
            tx.ins[idx].witness = scriptWitnessToWitnessStack(input.finalScriptWitness);
        }
        if (input.witnessUtxo) {
            inputAmount += input.witnessUtxo.value;
        }
        else if (input.nonWitnessUtxo) {
            var nwTx = nonWitnessUtxoTxFromCache(cache, input, idx);
            var vout = tx.ins[idx].index;
            var out = nwTx.outs[vout];
            inputAmount += out.value;
        }
    });
    var outputAmount = tx.outs.reduce(function (total, o) { return total + o.value; }, 0);
    var fee = inputAmount - outputAmount;
    if (fee < 0) {
        throw new Error('Outputs are spending more than Inputs');
    }
    var bytes = tx.virtualSize();
    cache.__FEE = fee;
    cache.__EXTRACTED_TX = tx;
    cache.__FEE_RATE = Math.floor(fee / bytes);
}
function nonWitnessUtxoTxFromCache(cache, input, inputIndex) {
    var c = cache.__NON_WITNESS_UTXO_TX_CACHE;
    if (!c[inputIndex]) {
        addNonWitnessTxCache(cache, input, inputIndex);
    }
    return c[inputIndex];
}
function getScriptFromUtxo(inputIndex, input, cache) {
    if (input.witnessUtxo !== undefined) {
        return input.witnessUtxo.script;
    }
    else if (input.nonWitnessUtxo !== undefined) {
        var nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(cache, input, inputIndex);
        return nonWitnessUtxoTx.outs[cache.__TX.ins[inputIndex].index].script;
    }
    else {
        throw new Error("Can't find pubkey in input without Utxo data");
    }
}
function pubkeyInInput(pubkey, input, inputIndex, cache) {
    var script = getScriptFromUtxo(inputIndex, input, cache);
    var meaningfulScript = getMeaningfulScript(script, inputIndex, 'input', input.redeemScript, input.witnessScript).meaningfulScript;
    return pubkeyInScript(pubkey, meaningfulScript);
}
function pubkeyInOutput(pubkey, output, outputIndex, cache) {
    var script = cache.__TX.outs[outputIndex].script;
    var meaningfulScript = getMeaningfulScript(script, outputIndex, 'output', output.redeemScript, output.witnessScript).meaningfulScript;
    return pubkeyInScript(pubkey, meaningfulScript);
}
function redeemFromFinalScriptSig(finalScript) {
    if (!finalScript)
        return;
    var decomp = bscript.decompile(finalScript);
    if (!decomp)
        return;
    var lastItem = decomp[decomp.length - 1];
    if (!Buffer.isBuffer(lastItem) ||
        isPubkeyLike(lastItem) ||
        isSigLike(lastItem))
        return;
    var sDecomp = bscript.decompile(lastItem);
    if (!sDecomp)
        return;
    return lastItem;
}
function redeemFromFinalWitnessScript(finalScript) {
    if (!finalScript)
        return;
    var decomp = scriptWitnessToWitnessStack(finalScript);
    var lastItem = decomp[decomp.length - 1];
    if (isPubkeyLike(lastItem))
        return;
    var sDecomp = bscript.decompile(lastItem);
    if (!sDecomp)
        return;
    return lastItem;
}
function isPubkeyLike(buf) {
    return buf.length === 33 && bscript.isCanonicalPubKey(buf);
}
function isSigLike(buf) {
    return bscript.isCanonicalScriptSignature(buf);
}
function getMeaningfulScript(script, index, ioType, redeemScript, witnessScript) {
    var isP2SH = isP2SHScript(script);
    var isP2SHP2WSH = isP2SH && redeemScript && isP2WSHScript(redeemScript);
    var isP2WSH = isP2WSHScript(script);
    if (isP2SH && redeemScript === undefined)
        throw new Error('scriptPubkey is P2SH but redeemScript missing');
    if ((isP2WSH || isP2SHP2WSH) && witnessScript === undefined)
        throw new Error('scriptPubkey or redeemScript is P2WSH but witnessScript missing');
    var meaningfulScript;
    if (isP2SHP2WSH) {
        meaningfulScript = witnessScript;
        checkRedeemScript(index, script, redeemScript, ioType);
        checkWitnessScript(index, redeemScript, witnessScript, ioType);
        checkInvalidP2WSH(meaningfulScript);
    }
    else if (isP2WSH) {
        meaningfulScript = witnessScript;
        checkWitnessScript(index, script, witnessScript, ioType);
        checkInvalidP2WSH(meaningfulScript);
    }
    else if (isP2SH) {
        meaningfulScript = redeemScript;
        checkRedeemScript(index, script, redeemScript, ioType);
    }
    else {
        meaningfulScript = script;
    }
    return {
        meaningfulScript: meaningfulScript,
        type: isP2SHP2WSH
            ? 'p2sh-p2wsh'
            : isP2SH
                ? 'p2sh'
                : isP2WSH
                    ? 'p2wsh'
                    : 'raw'
    };
}
function checkInvalidP2WSH(script) {
    if (isP2WPKH(script) || isP2SHScript(script)) {
        throw new Error('P2WPKH or P2SH can not be contained within P2WSH');
    }
}
function pubkeyInScript(pubkey, script) {
    var pubkeyHash = crypto_1.hash160(pubkey);
    var decompiled = bscript.decompile(script);
    if (decompiled === null)
        throw new Error('Unknown script error');
    return decompiled.some(function (element) {
        if (typeof element === 'number')
            return false;
        return element.equals(pubkey) || element.equals(pubkeyHash);
    });
}
function classifyScript(script) {
    if (isP2WPKH(script))
        return 'witnesspubkeyhash';
    if (isP2PKH(script))
        return 'pubkeyhash';
    if (isP2MS(script))
        return 'multisig';
    if (isP2PK(script))
        return 'pubkey';
    return 'nonstandard';
}
function range(n) {
    return Array(n).keys().slice();
}
