// Key derivation
export const KDF_HASH = 'sha512'
export const KDF_SALT_LENGTH = 32

// Cipher
export const AES_256_BLOCK_MODE = 'aes-256-gcm'
export const AES_256_GCM_KEY_LENGTH = 32
export const AES_256_GCM_IV_LENGTH = 12
export const AES_256_GCM_AUTH_TAG_LENGTH = 16

// HMAC
export const HMAC_HASH = 'sha512'
export const HMAC_KEY_LENGTH = 64
export const HMAC_OUTPUT_LENGTH = 64

// Protocol
export const HEADER_VERSION = '1a2g' // version 1, AES-256-GCM
export const HEADER_SIZE =
  HEADER_VERSION.length + AES_256_GCM_IV_LENGTH + KDF_SALT_LENGTH
export const BLOCK_SIZE = 16 * 1024 // 16kiB
export const CLEARTEXT_BLOCK_SIZE = BLOCK_SIZE
export const CIPHERTEXT_BLOCK_SIZE =
  2 + BLOCK_SIZE + AES_256_GCM_AUTH_TAG_LENGTH
export const MAX_PADDING_LENGTH = BLOCK_SIZE
