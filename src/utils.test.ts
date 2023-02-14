import crypto from 'node:crypto'
import { decodeHex, encodeHex } from './tests/codec'
import { compare, incrementLE, memzero } from './utils'

describe('utils', () => {
  test('memzero', () => {
    const z = new Uint8Array(32).fill(0)
    const x = new Uint8Array(crypto.randomBytes(32))
    memzero(x)
    expect(x).toEqual(z)
  })
  test('incrementLE', () => {
    const x = decodeHex('00000000')
    incrementLE(x)
    expect(encodeHex(x)).toEqual('01000000')
  })
  test('incrementLE carry', () => {
    const x = decodeHex('ff000000')
    incrementLE(x)
    expect(encodeHex(x)).toEqual('00010000')
  })
  test('incrementLE overflow', () => {
    const x = decodeHex('ffffffff')
    incrementLE(x)
    expect(encodeHex(x)).toEqual('00000000')
  })
  test('compare, different lengths', () => {
    const a = Buffer.from(decodeHex('0000'))
    const b = Buffer.from(decodeHex('000000'))
    expect(compare(a, b)).toBe(false)
  })
  test('compare, equal', () => {
    const a = Buffer.from(decodeHex('1234567890'))
    const b = Buffer.from(decodeHex('1234567890'))
    expect(compare(a, b)).toBe(true)
  })
  test('compare, different', () => {
    const a = Buffer.from(decodeHex('1234567890'))
    const b = Buffer.from(decodeHex('0987654321'))
    expect(compare(a, b)).toBe(false)
  })
})
