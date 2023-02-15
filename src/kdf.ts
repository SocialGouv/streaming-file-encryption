import crypto from 'node:crypto'
import {
  CIPHER_KEY_LENGTH,
  HMAC_HASH,
  HMAC_KEY_LENGTH,
  KDF_HASH,
} from './constants'
import { incrementLE, memzero } from './utils'

function deriveKey(
  mainSecret: Buffer | Uint8Array,
  salt: Buffer,
  context: string,
  outputSize: number
) {
  return new Promise<Buffer>((resolve, reject) => {
    crypto.hkdf(
      KDF_HASH,
      mainSecret,
      salt,
      context,
      outputSize,
      (error, derivedKey) => {
        if (error) {
          return reject(error)
        }
        resolve(Buffer.from(derivedKey))
      }
    )
  })
}

export async function deriveKeys(
  mainSecret: Buffer | Uint8Array,
  mainSalt: Buffer,
  context: string
) {
  const hmacSalt = Buffer.from(mainSalt)
  incrementLE(hmacSalt)
  const [cipherKey, hmacKey] = await Promise.all([
    deriveKey(mainSecret, mainSalt, context, CIPHER_KEY_LENGTH),
    deriveKey(mainSecret, hmacSalt, context, HMAC_KEY_LENGTH),
  ])
  memzero(hmacSalt)
  const hmac = crypto.createHmac(HMAC_HASH, hmacKey)
  memzero(hmacKey)
  return { cipherKey, hmac }
}
