import crypto from 'node:crypto'
import { compose } from 'node:stream'
import {
  CipherAlgorithm,
  CIPHERTEXT_BLOCK_SIZE,
  CIPHER_AUTH_TAG_LENGTH,
  CIPHER_IV_LENGTH,
  CLEARTEXT_BLOCK_SIZE,
  HEADER_SIZE,
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

function chunkedEncryption(
  mainSecret: Buffer | Uint8Array,
  context: string,
  algorithm: CipherAlgorithm
) {
  return async function* encryptChunk(source: AsyncIterable<Buffer>) {
    let blockIndex = 0
    const paddingBuffer = Buffer.alloc(CLEARTEXT_BLOCK_SIZE, 0x00)
    const iv = crypto.randomBytes(CIPHER_IV_LENGTH)
    const salt = crypto.randomBytes(KDF_SALT_LENGTH)
    const { cipherKey, hmac } = await deriveKeys(mainSecret, salt, context)
    const version = Buffer.from(
      algorithm === 'chacha20-poly1305'
        ? HEADER_VERSION_1c2p
        : HEADER_VERSION_1a2g
    )

    yield version
    hmac.update(version)
    // Make a copy when writing the IV to avoid same-tick increment
    // being backported to the output stream
    const ivOut = Buffer.from(iv)
    yield ivOut
    hmac.update(ivOut)
    yield salt
    hmac.update(salt)
    for await (const cleartext of source) {
      const cipher = crypto.createCipheriv(algorithm, cipherKey, iv, {
        // @ts-ignore
        authTagLength: CIPHER_AUTH_TAG_LENGTH,
      })
      cipher.setAAD(numberToUint32LE(blockIndex))
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
      blockIndex++
    }
    yield hmac.digest()
    memzero(cipherKey)
  }
}

function chunkedDecryption(mainSecret: Buffer | Uint8Array, context: string) {
  return async function* decryptChunk(source: AsyncIterable<Buffer>) {
    let cipherKey = Buffer.from([])
    let iv = Buffer.from([])
    let hmac: crypto.Hmac | undefined = undefined
    let isHeader = true
    let isDone = false
    let algorithm: CipherAlgorithm = 'aes-256-gcm'
    let blockIndex = 0
    for await (const block of source) {
      if (isHeader) {
        const v = block.subarray(0, HEADER_VERSION_LENGTH)
        if (v.toString() === HEADER_VERSION_1a2g) {
          algorithm = 'aes-256-gcm'
        } else if (v.toString() === HEADER_VERSION_1c2p) {
          algorithm = 'chacha20-poly1305'
        } else {
          throw new Error('Unsupported file type')
        }
        iv = block.subarray(
          HEADER_VERSION_LENGTH,
          HEADER_VERSION_LENGTH + CIPHER_IV_LENGTH
        )
        const salt = block.subarray(
          HEADER_VERSION_LENGTH + CIPHER_IV_LENGTH,
          HEADER_SIZE
        )
        ;({ cipherKey, hmac } = await deriveKeys(mainSecret, salt, context))
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
      const authTagLength = CIPHER_AUTH_TAG_LENGTH
      const cipher = crypto.createDecipheriv(algorithm, cipherKey, iv, {
        // @ts-ignore
        authTagLength,
      })
      cipher.setAAD(numberToUint32LE(blockIndex))
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
      blockIndex++
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
    rebuffer(0, CLEARTEXT_BLOCK_SIZE),
    chunkedEncryption(mainSecret, context, algorithm)
  )
}

export function decryptFile(mainSecret: Buffer | Uint8Array, context: string) {
  return compose(
    rebuffer(HEADER_SIZE, CIPHERTEXT_BLOCK_SIZE),
    chunkedDecryption(mainSecret, context)
  )
}
