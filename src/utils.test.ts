import crypto from 'node:crypto'
import { compare, incrementLE, memzero, numberToUint32LE } from './utils'

const deHex = (hex: string) => Buffer.from(hex, 'hex')

describe('utils', () => {
  test('memzero', () => {
    const z = Buffer.alloc(32)
    const x = crypto.randomBytes(32)
    memzero(x)
    expect(x).toEqual(z)
  })
  test('incrementLE', () => {
    const x = deHex('00000000')
    incrementLE(x)
    expect(x.toString('hex')).toEqual('01000000')
  })
  test('incrementLE carry', () => {
    const x = deHex('ff000000')
    incrementLE(x)
    expect(x.toString('hex')).toEqual('00010000')
  })
  test('incrementLE overflow', () => {
    const x = deHex('ffffffff')
    incrementLE(x)
    expect(x.toString('hex')).toEqual('00000000')
  })
  test('compare, different lengths', () => {
    const a = Buffer.from(deHex('0000'))
    const b = Buffer.from(deHex('000000'))
    expect(compare(a, b)).toBe(false)
  })
  test('compare, equal', () => {
    const a = Buffer.from(deHex('1234567890'))
    const b = Buffer.from(deHex('1234567890'))
    expect(compare(a, b)).toBe(true)
  })
  test('compare, different', () => {
    const a = Buffer.from(deHex('1234567890'))
    const b = Buffer.from(deHex('0987654321'))
    expect(compare(a, b)).toBe(false)
  })
  test('numberToUint32LE', () => {
    const n = numberToUint32LE
    expect(n(0x00000000)).toEqual(Buffer.from([0x00, 0x00, 0x00, 0x00]))
    expect(n(0x00000001)).toEqual(Buffer.from([0x01, 0x00, 0x00, 0x00]))
    expect(n(0x000000ff)).toEqual(Buffer.from([0xff, 0x00, 0x00, 0x00]))
    expect(n(0x00000100)).toEqual(Buffer.from([0x00, 0x01, 0x00, 0x00]))
    expect(n(0x12345678)).toEqual(Buffer.from([0x78, 0x56, 0x34, 0x12]))
  })
})
