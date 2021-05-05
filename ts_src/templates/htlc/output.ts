// OP_HASH160 {scriptHash} OP_EQUAL

import * as bscript from '../../script';
import { OPS } from '../../script';

export function check(script: Buffer | Array<number | Buffer>): boolean {
  const buffer = bscript.compile(script);

  return (
    buffer.length === 92 &&
    buffer[0] === OPS.OP_IF &&
    buffer[1] === OPS.OP_SHA256 && buffer[2] === 0x20 && buffer[35] === OPS.OP_EQUALVERIFY &&
    buffer[36] === OPS.OP_DUP &&
    buffer[37] === OPS.OP_HASH160 && buffer[38] === 0x14 &&
    buffer[59] === OPS.OP_ELSE &&
    buffer[60] === 0x3 &&
    buffer[64] === OPS.OP_CHECKLOCKTIMEVERIFY &&
    buffer[65] === OPS.OP_DROP &&
    buffer[66] === OPS.OP_DUP &&
    buffer[67] === OPS.OP_HASH160 &&
    buffer[68] === 0x14 &&
    buffer[89] === OPS.OP_ENDIF &&
    buffer[90] === OPS.OP_EQUALVERIFY &&
    buffer[91] === OPS.OP_CHECKSIG
  );
}
check.toJSON = (): string => {
  return 'htlc output';
};
