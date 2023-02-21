import crypto from 'node:crypto'
import { compose } from 'node:stream'
import {
  CipherAlgorithm,
  CIPHERTEXT_PAGE_LENGTH,
  CIPHER_AUTH_TAG_LENGTH,
  CIPHER_IV_LENGTH,
  CLEARTEXT_PAGE_LENGTH,
  HEADER_LENGTH,
  HEADER_VERSION_1a2g,
  HEADER_VERSION_1c2p,
  HEADER_VERSION_LENGTH,
  HMAC_OUTPUT_LENGTH,
  KDF_SALT_LENGTH,
} from './constants'
import { deriveKeys } from './kdf'
import { compare, incrementLE, memzero, numberToUint32LE } from './utils'

declare module 'node:stream' {
  export function compose(
    ...streams: (
      | Stream
      | Iterable<Buffer | string>
      | AsyncIterable<Buffer | string>
      | Function
    )[]
  ): Duplex
}

export function rebuffer(headerLength: number, bufferLength: number) {
  return async function* rebuffer(source: AsyncIterable<Buffer>) {
    const header = headerLength ? Buffer.alloc(headerLength) : null
    const buffer = Buffer.alloc(bufferLength)
    let hi = 0 // index of first available byte in the header
    let bi = 0 // index of first available byte in the buffer
    let headerEmitted = false
    for await (const chunk of source) {
      let ci = 0 // index of first byte to process in the incoming chunk
      let chunkBytesToRead = chunk.byteLength
      if (!headerEmitted && header) {
        const headerFreeSpace = headerLength - hi
        const chunkBytesToHeader = Math.min(headerFreeSpace, chunkBytesToRead)
        const slice = chunk.subarray(ci, ci + chunkBytesToHeader)
        header.set(slice, hi)
        chunkBytesToRead -= chunkBytesToHeader
        hi += chunkBytesToHeader
        ci += chunkBytesToHeader
        if (hi === headerLength) {
          yield Buffer.from(header)
          headerEmitted = true
        }
      }
      while (chunkBytesToRead > 0) {
        const bufferFreeSpace = bufferLength - bi
        const chunkBytesToBuffer = Math.min(bufferFreeSpace, chunkBytesToRead)
        const slice = chunk.subarray(ci, ci + chunkBytesToBuffer)
        buffer.set(slice, bi)
        chunkBytesToRead -= chunkBytesToBuffer
        bi += chunkBytesToBuffer
        ci += chunkBytesToBuffer
        if (bi === bufferLength) {
          yield Buffer.from(buffer)
          bi = 0
        }
      }
    }
    if (header && !headerEmitted) {
      throw new Error('Not enough data to emit header')
    }
    // Emit last (incomplete) buffer
    if (bi !== 0) {
      yield buffer.subarray(0, bi)
    }
  }
}

function pagedEncryption(
  mainSecret: Buffer | Uint8Array,
  context: string,
  algorithm: CipherAlgorithm
) {
  return async function* encryptPage(source: AsyncIterable<Buffer>) {
    let pageIndex = 0
    const pageBuffer = Buffer.alloc(2 + CLEARTEXT_PAGE_LENGTH)
    const iv = crypto.randomBytes(CIPHER_IV_LENGTH)
    const salt = crypto.randomBytes(KDF_SALT_LENGTH)
    const { cipherKey, hmac } = await deriveKeys(mainSecret, salt, context)
    const version = Buffer.from(
      algorithm === 'chacha20-poly1305'
        ? HEADER_VERSION_1c2p
        : HEADER_VERSION_1a2g
    )

    const header = Buffer.concat([version, iv, salt])
    hmac.update(header)
    yield header
    for await (const cleartext of source) {
      const cipher = crypto.createCipheriv(algorithm, cipherKey, iv, {
        // @ts-ignore
        authTagLength: CIPHER_AUTH_TAG_LENGTH,
      })
      cipher.setAAD(numberToUint32LE(pageIndex))
      pageBuffer.fill(0x00)
      pageBuffer[0] = cleartext.byteLength & 0xff
      pageBuffer[1] = (cleartext.byteLength >> 8) & 0xff
      pageBuffer.set(cleartext, 2)
      const ciphertext = cipher.update(pageBuffer)
      const final = cipher.final()
      const authTag = cipher.getAuthTag()
      hmac.update(ciphertext)
      hmac.update(final)
      hmac.update(authTag)
      yield ciphertext
      if (final.byteLength > 0) {
        yield final
      }
      yield authTag
      incrementLE(iv)
      pageIndex++
    }
    yield hmac.digest()
    memzero(cipherKey)
  }
}

function pagedDecryption(mainSecret: Buffer | Uint8Array, context: string) {
  return async function* decryptPage(source: AsyncIterable<Buffer>) {
    let cipherKey = Buffer.from([])
    let iv = Buffer.from([])
    let hmac: crypto.Hmac | undefined = undefined
    let isDone = false
    let algorithm: CipherAlgorithm = 'aes-256-gcm'
    let pageIndex = 0
    for await (const page of source) {
      if (page.byteLength === HEADER_LENGTH) {
        const v = page.subarray(0, HEADER_VERSION_LENGTH)
        if (v.toString() === HEADER_VERSION_1a2g) {
          algorithm = 'aes-256-gcm'
        } else if (v.toString() === HEADER_VERSION_1c2p) {
          algorithm = 'chacha20-poly1305'
        } else {
          throw new Error('Unsupported file type')
        }
        iv = page.subarray(
          HEADER_VERSION_LENGTH,
          HEADER_VERSION_LENGTH + CIPHER_IV_LENGTH
        )
        const salt = page.subarray(
          HEADER_VERSION_LENGTH + CIPHER_IV_LENGTH,
          HEADER_LENGTH
        )
        ;({ cipherKey, hmac } = await deriveKeys(mainSecret, salt, context))
        hmac.update(page)
        continue
      }
      if (page.byteLength === HMAC_OUTPUT_LENGTH) {
        if (!compare(page, hmac!.digest())) {
          throw new Error(
            'File decryption error: invalid HMAC (failed integrity check)'
          )
        }
        isDone = true
        continue
      }
      if (isDone) {
        throw new Error(
          'File decryption error: no more data is expected after HMAC verification'
        )
      }
      hmac!.update(page)
      const authTagLength = CIPHER_AUTH_TAG_LENGTH
      const cipher = crypto.createDecipheriv(algorithm, cipherKey, iv, {
        // @ts-ignore
        authTagLength,
      })
      cipher.setAAD(numberToUint32LE(pageIndex))
      const authTag = page.subarray(-authTagLength, page.byteLength)
      const ciphertext = page.subarray(0, -authTagLength)
      cipher.setAuthTag(authTag)
      const paddedCleartext = cipher.update(ciphertext)
      const final = cipher.final() // will throw if authentication fails
      const pageLength = (paddedCleartext[1] << 8) | paddedCleartext[0]
      yield paddedCleartext.subarray(2, 2 + pageLength)
      if (final.byteLength > 0) {
        yield final // Avoid yielding zero-length buffers to help with testing
      }
      incrementLE(iv)
      pageIndex++
    }
    memzero(cipherKey)
    if (!isDone) {
      throw new Error(
        'File decryption error: stream terminated before HMAC verification'
      )
    }
  }
}

export function encryptFile(
  mainSecret: Buffer | Uint8Array,
  context: string,
  algorithm: CipherAlgorithm = 'aes-256-gcm'
) {
  return compose(
    rebuffer(0, CLEARTEXT_PAGE_LENGTH),
    pagedEncryption(mainSecret, context, algorithm)
  )
}

export function decryptFile(mainSecret: Buffer | Uint8Array, context: string) {
  return compose(
    rebuffer(HEADER_LENGTH, CIPHERTEXT_PAGE_LENGTH),
    pagedDecryption(mainSecret, context)
  )
}
