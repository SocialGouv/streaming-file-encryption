import crypto from 'node:crypto'

export function memzero(buffer: Buffer) {
  for (let i = 0; i < buffer.byteLength; ++i) {
    buffer[i] = 0
  }
}

export function incrementLE(buffer: Buffer) {
  let add = 0
  let carry = 1
  for (let i = 0; i < buffer.byteLength; ++i) {
    add = buffer[i] + carry
    buffer[i] = add & 0xff
    carry = add >>> 8
  }
}

export function compare(a: Buffer, b: Buffer) {
  if (a.byteLength !== b.byteLength) {
    return false
  }
  return crypto.timingSafeEqual(a, b)
}

export function numberToUint32LE(input: number) {
  const buffer = new ArrayBuffer(4)
  const u32 = new Uint32Array(buffer)
  u32[0] = input
  return Buffer.from(buffer)
}
