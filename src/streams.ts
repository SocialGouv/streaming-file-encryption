import crypto from 'node:crypto'
import { compose } from 'node:stream'
import {
  AES_256_BLOCK_MODE,
  AES_256_GCM_AUTH_TAG_LENGTH,
  AES_256_GCM_IV_LENGTH,
  CIPHERTEXT_BLOCK_SIZE,
  CLEARTEXT_BLOCK_SIZE,
  HEADER_SIZE,
  HEADER_VERSION,
  HMAC_OUTPUT_LENGTH,
  KDF_SALT_LENGTH,
} from './constants'
import { deriveKeys } from './kdf'
import { compare, incrementLE, memzero } from './utils'

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

export function rebuffer(headerSize: number, bufferSize: number) {
  return async function* rebuffer(source: AsyncIterable<Buffer>) {
    const header = headerSize ? Buffer.alloc(headerSize) : null
    const buffer = Buffer.alloc(bufferSize)
    let hi = 0 // index of first available byte in the header
    let bi = 0 // index of first available byte in the buffer
    let headerEmitted = false
    for await (const chunk of source) {
      let ci = 0 // index of first byte to process in the incoming chunk
      let chunkBytesToRead = chunk.byteLength
      if (!headerEmitted && header) {
        const headerFreeSpace = headerSize - hi
        const chunkBytesToHeader = Math.min(headerFreeSpace, chunkBytesToRead)
        const slice = chunk.subarray(ci, ci + chunkBytesToHeader)
        header.set(slice, hi)
        chunkBytesToRead -= chunkBytesToHeader
        hi += chunkBytesToHeader
        ci += chunkBytesToHeader
        if (hi === headerSize) {
          yield Buffer.from(header)
          headerEmitted = true
        }
      }
      while (chunkBytesToRead > 0) {
        const bufferFreeSpace = bufferSize - bi
        const chunkBytesToBuffer = Math.min(bufferFreeSpace, chunkBytesToRead)
        const slice = chunk.subarray(ci, ci + chunkBytesToBuffer)
        buffer.set(slice, bi)
        chunkBytesToRead -= chunkBytesToBuffer
        bi += chunkBytesToBuffer
        ci += chunkBytesToBuffer
        if (bi === bufferSize) {
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

function chunkedEncryption(mainSecret: Buffer | Uint8Array, context: string) {
  return async function* encryptChunk(source: AsyncIterable<Buffer>) {
    const paddingBuffer = Buffer.alloc(CLEARTEXT_BLOCK_SIZE, 0x00)
    const iv = crypto.randomBytes(AES_256_GCM_IV_LENGTH)
    const salt = crypto.randomBytes(KDF_SALT_LENGTH)
    const { aesKey, hmac } = await deriveKeys(mainSecret, salt, context)
    const version = Buffer.from(HEADER_VERSION)

    yield version
    hmac.update(version)
    const ivOut = Buffer.from(iv)
    // Make a copy when writing the IV to avoid same-tick increment
    // being backported to the output stream
    yield ivOut
    hmac.update(ivOut)
    yield salt
    hmac.update(salt)
    for await (const cleartext of source) {
      const cipher = crypto.createCipheriv(AES_256_BLOCK_MODE, aesKey, iv, {
        authTagLength: AES_256_GCM_AUTH_TAG_LENGTH,
      })
      const paddingSize = Math.max(
        0,
        CLEARTEXT_BLOCK_SIZE - cleartext.byteLength
      )
      const blockSizeMark = Buffer.from([
        cleartext.byteLength & 0xff,
        (cleartext.byteLength >> 8) & 0xff,
      ])
      const paddedClearText = Buffer.concat([
        blockSizeMark,
        cleartext,
        paddingBuffer.subarray(0, paddingSize),
      ])
      const ciphertext = cipher.update(paddedClearText)
      yield ciphertext
      hmac.update(ciphertext)
      const final = cipher.final()
      if (final.byteLength > 0) {
        yield final
        hmac.update(final)
      }
      const authTag = cipher.getAuthTag()
      yield authTag
      hmac.update(authTag)
      incrementLE(iv)
    }
    yield hmac.digest()
    memzero(aesKey)
  }
}

function chunkedDecryption(mainSecret: Buffer | Uint8Array, context: string) {
  return async function* decryptChunk(source: AsyncIterable<Buffer>) {
    let aesKey = Buffer.from([])
    let iv = Buffer.from([])
    let hmac: crypto.Hmac | undefined = undefined
    let isHeader = true
    let isDone = false
    for await (const block of source) {
      if (isHeader) {
        const v = block.subarray(0, HEADER_VERSION.length)
        if (v.toString() !== HEADER_VERSION) {
          throw new Error('Unsupported file type')
        }
        iv = block.subarray(
          HEADER_VERSION.length,
          HEADER_VERSION.length + AES_256_GCM_IV_LENGTH
        )
        const salt = block.subarray(
          HEADER_VERSION.length + AES_256_GCM_IV_LENGTH,
          HEADER_SIZE
        )
        ;({ aesKey, hmac } = await deriveKeys(mainSecret, salt, context))
        hmac.update(v)
        hmac.update(iv)
        hmac.update(salt)
        isHeader = false
        continue
      }
      if (block.byteLength === HMAC_OUTPUT_LENGTH) {
        if (!compare(block, hmac!.digest())) {
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
      hmac!.update(block)
      const authTagLength = AES_256_GCM_AUTH_TAG_LENGTH
      const cipher = crypto.createDecipheriv(AES_256_BLOCK_MODE, aesKey, iv, {
        authTagLength,
      })
      const authTag = block.subarray(-authTagLength, block.byteLength)
      const ciphertext = block.subarray(0, -authTagLength)
      cipher.setAuthTag(authTag)
      const paddedCleartext = cipher.update(ciphertext)
      const final = cipher.final() // will throw if authentication fails
      const blockLength = (paddedCleartext[1] << 8) | paddedCleartext[0]
      yield paddedCleartext.subarray(2, 2 + blockLength)
      if (final.byteLength > 0) {
        yield final // Avoid yielding zero-length buffers to help with testing
      }
      incrementLE(iv)
    }
    memzero(aesKey)
    if (!isDone) {
      throw new Error(
        'File decryption error: stream terminated before HMAC verification'
      )
    }
  }
}

export function encryptFile(mainSecret: Buffer | Uint8Array, context: string) {
  return compose(
    rebuffer(0, CLEARTEXT_BLOCK_SIZE),
    chunkedEncryption(mainSecret, context)
  )
}

export function decryptFile(mainSecret: Buffer | Uint8Array, context: string) {
  return compose(
    rebuffer(HEADER_SIZE, CIPHERTEXT_BLOCK_SIZE),
    chunkedDecryption(mainSecret, context)
  )
}
