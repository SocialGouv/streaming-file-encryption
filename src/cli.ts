import parseArgs, { ParsedArgs } from 'minimist'
import { pipeline } from 'node:stream/promises'
import {
  decodeMainSecret,
  decryptFile,
  encryptFile,
  generateSerializedMainSecret,
} from './index'

function loadCipherArguments(args: ParsedArgs) {
  const mainSecret = process.env.MAIN_SECRET
  if (!mainSecret) {
    console.error('Missing MAIN_SECRET environment variable')
    process.exit(1)
  }
  if (!args.context) {
    console.error('Missing --context argument')
    process.exit(1)
  }
  return {
    mainSecret: decodeMainSecret(mainSecret),
    context: args.context,
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2), {
    alias: {
      help: 'h',
      context: ['c', 'ctx'],
      algorithm: ['a', 'alg'],
    },
  })
  const action = args._[0]
  if (args.help || action === 'help') {
    console.info(`Streaming File Encryption CLI

Commands:

    generate          Generate a main secret as an environment variable export
    encrypt           Encrypt a file
    decrypt           Decrypt a file

Encryption and decryption both require a main secret to be passed
via the \`MAIN_SECRET\` environment variable.

Encryption and decryption requires a context string to be passed
via the --context flag (aliases: -c or --ctx).

Encryption can optionally specify the cipher algorithm to use,
via the --algorithm flag (aliases: -a or --alg).
Values are \`aes-256-gcm\` (default) or \`chacha20-poly1305\`.

Files are read from the standard input, and written to standard output.

Example usage:

$ npx @socialgouv/streaming-file-encryption generate
$ export MAIN_SECRET=0123456789abcdef...
$ npx @socialgouv/streaming-file-encryption encrypt --context foo < document.pdf > document.pdf.sfe
$ npx @socialgouv/streaming-file-encryption decrypt --context foo < document.pdf.sfe > decrypted.pdf
`)
    process.exit(0)
  }

  if (action === 'encrypt') {
    const { mainSecret, context } = loadCipherArguments(args)
    const algorithm = args.algorithm ?? 'aes-256-gcm'
    if (!['aes-256-gcm', 'chacha20-poly1305'].includes(algorithm)) {
      console.error(
        'Invalid algorithm: only `aes-256-gcm` and `chacha20-poly1305` are supported.'
      )
    }
    await pipeline(
      process.stdin,
      encryptFile(mainSecret, context, algorithm),
      process.stdout
    )
  } else if (action === 'decrypt') {
    const { mainSecret, context } = loadCipherArguments(args)
    await pipeline(
      process.stdin,
      decryptFile(mainSecret, context),
      process.stdout
    )
  } else if (action === 'generate') {
    console.info(`export MAIN_SECRET=${generateSerializedMainSecret()}`)
  } else {
    console.error(
      'Invalid action: first argument should be `encrypt`, `decrypt`, or `generate`.'
    )
    process.exit(1)
  }
}

main()
