import { Readable } from 'node:stream'

export function sourceStream(bufferSizes: number[]) {
  function* source() {
    let x = 0
    for (const bufferSize of bufferSizes) {
      const buffer = Buffer.alloc(bufferSize)
      // Generate a ramp
      for (let i = 0; i < buffer.byteLength; ++i) {
        buffer[i] = x
        x = (x + 1) & 0xff
      }
      yield buffer
    }
  }
  return Readable.from(source())
}

export function observe(onBuffer: (x: Buffer) => void) {
  return async function* observer(source: AsyncIterable<Buffer>) {
    for await (const buffer of source) {
      onBuffer(buffer)
      yield buffer
    }
  }
}

export function expectOutputSequence(spy: jest.Mock, sequence: number[]) {
  expect(spy).toHaveBeenCalledTimes(sequence.length)
  let x = 0
  sequence.forEach((length, i) => {
    const buffer = spy.mock.calls[i][0]
    expect(buffer.byteLength).toEqual(length)
    // Make sure the sequence is correct
    for (let i = 0; i < buffer.byteLength; ++i) {
      expect(buffer[i]).toEqual(x)
      x = (x + 1) & 0xff
    }
  })
}
