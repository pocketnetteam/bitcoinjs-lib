// OP_HASH160 {scriptHash} OP_EQUAL

import * as bscript from '../../script';
import { OPS } from '../../script';

export function check(script: Buffer | Array<number | Buffer>): boolean {
  const buffer = bscript.compile(script);

  return (
    buffer.length === 93 &&
    buffer[1] === OPS.OP_IF &&
    buffer[2] === OPS.OP_SHA256 && buffer[3] === 0x20 && buffer[36] === OPS.OP_EQUALVERIFY &&
    buffer[37] === OPS.OP_DUP &&
    buffer[38] === OPS.OP_HASH160 && buffer[39] === 0x14 &&
    buffer[60] === OPS.OP_ELSE &&
    buffer[61] === 0x3 &&
    buffer[65] === OPS.OP_CHECKLOCKTIMEVERIFY &&
    buffer[66] === OPS.OP_DROP &&
    buffer[67] === OPS.OP_DUP &&
    buffer[68] === OPS.OP_HASH160 &&
    buffer[69] === 0x14 &&
    buffer[90] === OPS.OP_ENDIF &&
    buffer[91] === OPS.OP_EQUALVERIFY &&
    buffer[92] === OPS.OP_CHECKSIG
  );
}
check.toJSON = (): string => {
  return 'htlc output';
};
