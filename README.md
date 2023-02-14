# `@socialgouv/streaming-file-encryption`

Streaming encryption/decryption for files in Node.js made simple and secure.

## Installation

```shell
pnpm add @socialgouv/streaming-file-encryption
yarn add @socialgouv/streaming-file-encryption
npm i @socialgouv/streaming-file-encryption
```

## Usage

> _**Note**: requires Node.js v15 or superior._

You will need the following to get started:

1. A main secret, which can be generated in Node.js:

```ts
import crypto from 'node:crypto'

// The length should be between 32 and 256 bytes,
// and must be issued from a CSPRNG:
console.info(crypto.randomBytes(64).toString('hex'))
```

### Encrypting & decrypting files

The `context` argument should be a string used to further isolate key derivation.

It can be any string (even empty if you don't wish to use it), but the same
context that was used for encryption has to be provided when attempting to
decrypt a file.

You could store this context in your database, but make sure it's an immutable
record, like a foreign key. UUIDs are ideal for this kind of application.

```ts
import { encryptFile, decryptFile } from '@socialgouv/streaming-file-encryption'
import fs from 'node:fs'
import { pipeline } from 'node:stream/promises'

await pipeline(
  fs.createReadStream('cleartext.ext'),
  encryptFile(mainSecret, context),
  fs.createWriteStream('ciphertext.enc')
)

await pipeline(
  fs.createReadStream('ciphertext.enc'),
  decryptFile(mainSecret, context),
  fs.createWriteStream('cleartext.ext')
)
```

## Security

Internally, the key used to encrypt the file will be derived from:

1. Your main secret
2. The context you provided
3. An internal random salt, stored in the output ciphertext file

The security of this system requires knowing all three of these informations
before being able to decrypt a file. It is then essential to keep them separate,
for example:

1. The main secret is only known by the application server
2. The context is stored in a database
3. The encrypted files are stored on a separate storage server

It should require an attacker to break all three of your systems to be able to
recompose individual file keys.

### Properties

Encrypted files have the following properties:

- Resistance to tampering (modifying data in-place)
- Resistance to truncation (removing data at either end or in the middle)
- Resistance to extension (adding data at either end or in the middle)
- Resistance to reordering (swapping blocks of data)

## Cryptography

### Overview

There are two cryptographic parts to performing encryption and decryption:

1. Obtaining keys via key derivation
2. Encrypting and decrypting the contents of a file

Key derivation is done using `HKDF-SHA512`.

Symmetric encryption is done using `AES-256-GCM` on blocks of 16kiB of
cleartext at a time.

Final message authentication is done using `HMAC-SHA512`.

### Key derivation

We generate a random 32 byte salt `S`.

Two keys are derived using `HKDF-SHA512`:

One is for AES, using the main secret, the context and the salt `S`, giving
an output key of 32 bytes (256 bits).

One is for HMAC, using the main secret, the context and a salt `S + 1` (little
endian incrementation), giving an output key of 64 bytes.

The purpose of the salt is to add entropy to key derivation aside from the two
sources provided by the user (main secret & context). Differentiation via the
salt ensures no key material is shared between AES and HMAC.

### File encryption

We generate a random IV (12 bytes) `IV`.

The ciphertext file starts with a 48 bytes header containing:

- A four-byte version marker `1a2g`
- the IV
- the salt used for AES key derivation

The plain-text is broken down into blocks of 16kiB (16384 bytes) to be
encrypted individually with AES-256-GCM.

Clear-text input blocks are zero-padded (padding after data) to ensure a
constant length of 16kiB. The actual data length is encoded on two bytes
(little endian), and prepended to the block to encrypt:

```
cleartext input: "hello, world!"

Block to encrypt
0d 00                                     data length (decimal 13)
68 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21    message
00 00 00 00 00 00 00 00 00 00 00 00 00    padding (16371 bytes of zeros)
```

The first block will use the AES key obtained during key derivation and the IV.

Subsequent blocks will then increment the IV (in a little-endian manner).

The AES-256-GCM authentication tag is appended after the associated ciphertext.

HMAC is computed over everything from the first byte of the version identifier
in the header to the last byte of the authentication tag of the last block,
and placed at the end (last 64 bytes) of the file.

Therefore, the binary file structure looks like this:

```
Header
31 61 32 67 aa aa aa aa aa aa aa aa aa aa aa aa  |  Version + IV
bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  |  Salt (LSB)
bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  |  Salt (MSB)

Block 1
cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  |  Block 1 ciphertext
...............................................  |  (16386 bytes total)
cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  |  Block 1 ciphertext
dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd  |  Block 1 authentication tag

Block 2
ee ee ee ee ee ee ee ee ee ee ee ee ee ee ee ee  |  Block 2 ciphertext
...............................................  |  (16386 bytes total)
ee ee ee ee ee ee ee ee ee ee ee ee ee ee ee ee  |  Block 2 ciphertext
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff  |  Block 2 authentication tag

HMAC
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  |  HMAC-SHA512
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  |  of everything
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  |  until
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  |  this point
```

Version is the ASCII string `1a2g` (hex `31 61 32 67`)

When decrypting a file:

1. The IV and salt are first extracted from the header
2. Key derivation is performed with the main secret, salt and context
3. For each block:
   - The IV is incremented accordingly to the block number
   - The authentication tag is read from the end of the
     block and passed to the cipher
   - The ciphertext is decrypted and authenticated
   - The ciphertext is added to HMAC
4. HMAC is compared to the one present in the file for integrity checking

## FAQ

### Why HMAC? Isn't AES-GCM already authenticated?

For a single-block file, the final HMAC is indeed redundant with the authenticated
encryption of AES-GCM.

However, consider an input file spanning multiple blocks of 16kiB. While the
IV incrementation ensures that blocks can't be reordered or skipped, there are
no guarantees on truncating blocks at either end: you could drop the first block
and increment the IV in the header to truncate the head of the file, and you
could simply drop the last N blocks completely undetected, truncating the tail
of the file.

Adding the HMAC (which covers everything behind it) pins the start and end block
by both authenticating the IV and every block coming after it.

### My {few bytes} file ends up in a huge ciphertext, what's going on?

Blocks are of fixed size of 16kiB, with the input being zero-padded before
being encrypted.

This has the advantage of hiding the cleartext true size, at the cost of extra
storage overhead for encrypted files.

16kiB was chosen as a trade-off between the default buffer size in Node.js
filesystem I/O streams (64kiB) and the overhead added by having constant block
sizes. While higher buffer size offered better CPU performance, they came with
extra storage and RAM usage costs, so 16kiB was chosen as a middle ground.

## Code signature

This package is signed with [`sceau`](https://github.com/47ng/sceau).

The signature can be verified using the following public key:

```shell
sceau verify --publicKey cc5ce1aae47615906725d9859ae6c9202ca4406e14f242a4d1ef8a5a2cdadfb7
```

## License

[Apache-2.0](./LICENSE)
