export function memzero(buffer: Uint8Array) {
  for (let i = 0; i < buffer.byteLength; ++i) {
    buffer[i] = 0
  }
}

export function incrementLE(buffer: Uint8Array) {
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
  let ok = true
  for (let i = 0; i < a.byteLength; ++i) {
    ok &&= a[i] === b[i]
  }
  return ok
}
