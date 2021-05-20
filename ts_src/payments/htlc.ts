import * as bcrypto from '../crypto';
import { bitcoin as BITCOIN_NETWORK } from '../networks';
import * as bscript from '../script';
import * as address from '../address';
const ecc = require('tiny-secp256k1');
import {
  Payment,
  PaymentOpts,
  StackFunction,
} from './index';
import * as lazy from './lazy';
const typef = require('typeforce');
const OPS = bscript.OPS;

const bs58check = require('bs58check');
/*
function stacksEqual(a: Buffer[], b: Buffer[]): boolean {
  if (a.length !== b.length) return false;

  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}*/

function clearscript(asm: string): string {
    return asm.replace(/\n\t/g, '').replace(/\s{2,}/g, ' ').replace(/^\s+/, '').replace(/\s+$/, '');
  }


// input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL
export function htlc(a: Payment, opts?: PaymentOpts): Payment {
  if (!a.address && !a.htlc && !a.hash && !a.output && /*!a.redeem && */!a.input && !a.pubkey && !a.signature)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});

  typef(
    {
      network: typef.maybe(typef.Object),
      pubkey: typef.maybe(ecc.isPoint),
      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(23)),
      htlc : typef.maybe(typef.Object), ///?

      /*redeem: typef.maybe({
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.Buffer),
        input: typef.maybe(typef.Buffer),
        witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      }),*/

      input: typef.maybe(typef.Buffer),
      //witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      signature: typef.maybe(bscript.isCanonicalScriptSignature),
    },
    a,
  );

  let network = a.network;

  if (!network) {
    network = (a.redeem && a.redeem.network) || BITCOIN_NETWORK;
  }

  const o: Payment = { network };

  const _address = lazy.value(() => {
    const payload = bs58check.decode(a.address);
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });

  const _chunks = lazy.value(() => {
    return bscript.decompile(a.input!);
  }) as StackFunction;

  /*const _redeem = lazy.value(
    (): Payment => {
      const chunks = _chunks();
      return {
        network,
        output: chunks[chunks.length - 1] as Buffer,
        input: bscript.compile(chunks.slice(0, -1)),
        witness: a.witness || [],
      };
    },
  ) as PaymentFunction;*/

  // output dependents
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;

    const payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(o.network!.scriptHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });

  lazy.prop(o, 'htlc', () => {
      
    return a.htlc

  });

  lazy.prop(o, 'hash', () => {
    // in order of least effort
    if (a.output) return a.output.slice(3, 23);
    if (a.address) return _address().hash;
    if (o.redeem && o.redeem.output) return bcrypto.hash160(o.redeem.output);
  });

  lazy.prop(o, 'pubkey', () => {
    if (!a.input) return;
    return _chunks()[1] as Buffer;
  });

  lazy.prop(o, 'signature', () => {
    if (!a.input) return;
    return _chunks()[0] as Buffer;
  });

  lazy.prop(o, 'input', () => {
    if (!a.pubkey) return;
    if (!a.signature) return;

    var secret = ''

    if (a.htlc && a.htlc.secret) secret = a.htlc.secret


    console.log("input", a.signature.toString('hex'), bcrypto.hash160(a.pubkey).toString('hex'), bcrypto.sha256(Buffer.from(secret)).toString('hex'))

    return bscript.compile([a.signature, a.pubkey, Buffer.from(secret)]);
  });

  lazy.prop(o, 'witness', () => {
    if (!o.input) return;
    return [];
  });
  
  lazy.prop(o, 'output', () => {
    if (!o.htlc) return;

    var senderhash = address.fromBase58Check(o.htlc.sender).hash
    var recieverhash = address.fromBase58Check(o.htlc.reciever).hash
    var lockbuf = bscript.number.encode(o.htlc.lock)
    var hash = o.htlc.secret ? bcrypto.sha256(Buffer.from(o.htlc.secret)).toString('hex') : o.htlc.secrethash


    var asm2 = clearscript(`
        OP_DUP
        OP_IF
            OP_SHA256 ${hash} OP_EQUALVERIFY
            OP_DUP 
            OP_HASH160 ${recieverhash.toString('hex')}
        OP_ELSE
            ${lockbuf.toString('hex')} OP_CHECKLOCKTIMEVERIFY 
            OP_DROP 
            OP_DUP 
            OP_HASH160 ${senderhash.toString('hex')}
        OP_ENDIF
        OP_EQUALVERIFY
        OP_CHECKSIG
    `)


    return bscript.fromASM(asm2)

  });

  // input dependents
  /*lazy.prop(o, 'redeem', () => {
    if (!a.input) return;
    return _redeem();
  });*/

  /*lazy.prop(o, 'input', () => {
    if (!a.redeem || !a.redeem.input || !a.redeem.output) return;
    return bscript.compile(
      ([] as Stack).concat(
        bscript.decompile(a.redeem.input) as Stack,
        a.redeem.output,
      ),
    );
  });*/

  /*lazy.prop(o, 'witness', () => {
    if (o.redeem && o.redeem.witness) return o.redeem.witness;
    if (o.input) return [];
  });*/

  lazy.prop(o, 'name', () => {
    const nameParts = ['htlc'];
    if (o.redeem !== undefined && o.redeem.name !== undefined)
      nameParts.push(o.redeem.name!);
    return nameParts.join('-');
  });

  if (opts.validate) {

    let hash: Buffer = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.scriptHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }

    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }

    if (a.output) {

        var valid = (a.output.length === 93 &&
            a.output[0] === OPS.OP_DUP &&
            a.output[1] === OPS.OP_IF &&
            a.output[2] === OPS.OP_SHA256 && a.output[3] === 0x20 && a.output[36] === OPS.OP_EQUALVERIFY &&
            a.output[37] === OPS.OP_DUP &&
            a.output[38] === OPS.OP_HASH160 && a.output[39] === 0x14 &&
            a.output[60] === OPS.OP_ELSE &&
            a.output[61] === 0x3 &&
            a.output[65] === OPS.OP_CHECKLOCKTIMEVERIFY &&
            a.output[66] === OPS.OP_DROP &&
            a.output[67] === OPS.OP_DUP &&
            a.output[68] === OPS.OP_HASH160 &&
            a.output[69] === 0x14 &&
            a.output[90] === OPS.OP_ENDIF &&
            a.output[91] === OPS.OP_EQUALVERIFY &&
            a.output[92] === OPS.OP_CHECKSIG) 
            

        if(!valid) throw new TypeError('Output is invalid');

        const hash2 = a.output.slice(0, 93);
        if (hash.length > 0 && !hash.equals(hash2))
            throw new TypeError('Hash mismatch');
        else hash = hash2;
    }   


    /*// inlined to prevent 'no-inner-declarations' failing
    const checkRedeem = (redeem: Payment): void => {
      // is the redeem output empty/invalid?
      if (redeem.output) {
        const decompile = bscript.decompile(redeem.output);
        if (!decompile || decompile.length < 1)
          throw new TypeError('Redeem.output too short');

        // match hash against other sources
        const hash2 = bcrypto.hash160(redeem.output);
        if (hash.length > 0 && !hash.equals(hash2))
          throw new TypeError('Hash mismatch');
        else hash = hash2;
      }

      if (redeem.input) {
        const hasInput = redeem.input.length > 0;
        const hasWitness = redeem.witness && redeem.witness.length > 0;
        if (!hasInput && !hasWitness) throw new TypeError('Empty input');
        if (hasInput && hasWitness)
          throw new TypeError('Input and witness provided');
        if (hasInput) {
          const richunks = bscript.decompile(redeem.input) as Stack;
          if (!bscript.isPushOnly(richunks))
            throw new TypeError('Non push-only scriptSig');
        }
      }
    };*/

    /*if (a.input) {
      const chunks = _chunks();
      if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
      if (!Buffer.isBuffer(_redeem().output))
        throw new TypeError('Input is invalid');

      //checkRedeem(_redeem());
    }*/

    /*if (a.redeem) {
      if (a.redeem.network && a.redeem.network !== network)
        throw new TypeError('Network mismatch');
      if (a.input) {
        const redeem = _redeem();
        if (a.redeem.output && !a.redeem.output.equals(redeem.output!))
          throw new TypeError('Redeem.output mismatch');
        if (a.redeem.input && !a.redeem.input.equals(redeem.input!))
          throw new TypeError('Redeem.input mismatch');
      }

      checkRedeem(a.redeem);
    }*/

    /*if (a.witness) {
      if (
        a.redeem &&
        a.redeem.witness &&
        !stacksEqual(a.redeem.witness, a.witness)
      )
        throw new TypeError('Witness and redeem.witness mismatch');
    }*/
  }

  return Object.assign(o, a);
}
