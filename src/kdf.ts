import crypto from 'node:crypto'
import {
  AES_256_GCM_KEY_LENGTH,
  HMAC_HASH,
  HMAC_KEY_LENGTH,
  KDF_HASH,
} from './constants'
import { incrementLE, memzero } from './utils'

function deriveKey(
  mainSecret: Uint8Array,
  salt: Uint8Array,
  context: string,
  outputSize: number
) {
  return new Promise<Uint8Array>((resolve, reject) => {
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
        resolve(new Uint8Array(derivedKey))
      }
    )
  })
}

export async function deriveKeys(
  mainSecret: Uint8Array,
  mainSalt: Uint8Array,
  context: string
) {
  const hmacSalt = Buffer.from(mainSalt)
  incrementLE(hmacSalt)
  const [aesKey, hmacKey] = await Promise.all([
    deriveKey(mainSecret, mainSalt, context, AES_256_GCM_KEY_LENGTH),
    deriveKey(mainSecret, hmacSalt, context, HMAC_KEY_LENGTH),
  ])
  memzero(hmacSalt)
  const hmac = crypto.createHmac(HMAC_HASH, hmacKey)
  memzero(hmacKey)
  return { aesKey, hmac }
}
