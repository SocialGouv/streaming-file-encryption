// Key derivation
export const KDF_HASH = 'sha512'
export const KDF_SALT_LENGTH = 32

// Cipher
export type CipherAlgorithm = 'aes-256-gcm' | 'chacha20-poly1305'
export const CIPHER_KEY_LENGTH = 32
export const CIPHER_IV_LENGTH = 12
export const CIPHER_AUTH_TAG_LENGTH = 16

// HMAC
export const HMAC_HASH = 'sha512'
export const HMAC_KEY_LENGTH = 64
export const HMAC_OUTPUT_LENGTH = 64

// Protocol
export const HEADER_VERSION_LENGTH = 4
export const HEADER_VERSION_1a2g = '1a2g' // version 1, AES-256-GCM
export const HEADER_VERSION_1c2p = '1c2p' // version 1, ChaCha20-Poly1305

export const HEADER_LENGTH =
  HEADER_VERSION_LENGTH + CIPHER_IV_LENGTH + KDF_SALT_LENGTH
export const PAGE_LENGTH = 16 * 1024 // 16kiB
export const CLEARTEXT_PAGE_LENGTH = PAGE_LENGTH
export const CIPHERTEXT_PAGE_LENGTH = 2 + PAGE_LENGTH + CIPHER_AUTH_TAG_LENGTH
export const MAX_PADDING_LENGTH = PAGE_LENGTH
