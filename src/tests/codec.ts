export function decodeHex(serialized: string) {
  return new Uint8Array(Buffer.from(serialized, 'hex'))
}

export function encodeHex(buffer: Uint8Array) {
  return Buffer.from(buffer).toString('hex')
}
