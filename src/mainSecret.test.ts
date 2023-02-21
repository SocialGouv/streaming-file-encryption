import { decodeMainSecret, generateMainSecret } from './mainSecret'

test('main secret utils', () => {
  const a = generateMainSecret()
  const b = decodeMainSecret(a)
  expect(a).toMatch(/^[0-9a-f]{128}$/)
  expect(b.byteLength).toEqual(64)
})
