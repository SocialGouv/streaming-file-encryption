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
      context: ['c', 'ctx'],
    },
  })
  const action = args._[0]
  if (action === 'encrypt') {
    const { mainSecret, context } = loadCipherArguments(args)
    await pipeline(
      process.stdin,
      encryptFile(mainSecret, context),
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
