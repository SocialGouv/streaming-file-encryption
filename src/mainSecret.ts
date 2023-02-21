import crypto from 'node:crypto'

/**
 * Generate a 64 byte hex-encoded main secret string.
 *
 * @returns a hex-encoded string representation (128 hex characters)
 */
export function generateSerializedMainSecret() {
  return crypto.randomBytes(64).toString('hex')
}

/**
 * Decode a serialized main secret to a Buffer.
 *
 * @param serialized hex-encoded string of 64 bytes (128 hex characters)
 * @returns
 */
export function decodeMainSecret(serialized: string) {
  if (/^[0-9a-f]{128}$/i.test(serialized) === false) {
    throw new TypeError(
      'Invalid main secret format: should be 64 bytes hex-encoded.'
    )
  }
  return Buffer.from(serialized, 'hex')
}
