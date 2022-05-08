import * as bip32 from 'bip32';
import * as address from './address';
import * as crypto from './crypto';
import * as ECPair from './ecpair';
import * as networks from './networks';
import * as payments from './payments';
import * as script from './script';
import bip39Fork from './bip39'

const ecc = require('../editedmodules/tiny-secp256k1');

export { ECPair, address, bip32,  bip39Fork as bip39, crypto, networks, payments, script, ecc };

export { Block } from './block';
export { Psbt, PsbtTxInput, PsbtTxOutput } from './psbt';
export { OPS as opcodes } from './script';
export { Transaction } from './transaction';
export { TransactionBuilder } from './transaction_builder';

export { BIP32Interface } from 'bip32';
export { ECPairInterface, Signer, SignerAsync } from './ecpair';
export { Network } from './networks';
export {
  Payment,
  PaymentCreator,
  PaymentOpts,
  Stack,
  StackElement,
} from './payments';
export { OpCode } from './script';
export { Input as TxInput, Output as TxOutput } from './transaction';
