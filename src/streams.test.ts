import { createWriteStream } from 'node:fs'
import { pipeline } from 'node:stream/promises'
import { rebuffer } from './streams'
import { expectOutputSequence, observe, sourceStream } from './tests/streams'

type RebufferArgs = {
  bufferSize: number
  header?: number
}

function testRebufferSequence(
  inputSequence: number[],
  { bufferSize, header = 0 }: RebufferArgs,
  outputSequence: number[],
  expectFailure = false
) {
  return async () => {
    const spy = jest.fn()
    const source = sourceStream(inputSequence)
    const watch = observe(spy)
    const sink = createWriteStream('/dev/null')
    if (expectFailure) {
      await expect(() =>
        pipeline(source, rebuffer(header, bufferSize), watch, sink)
      ).rejects.toThrow()
      return
    }
    await pipeline(source, rebuffer(header, bufferSize), watch, sink)
    expectOutputSequence(spy, outputSequence)
  }
}

describe('streams/rebuffer', () => {
  test(
    'identity',
    testRebufferSequence(
      [32, 32, 32, 32],
      {
        bufferSize: 32,
      },
      [32, 32, 32, 32]
    )
  )
  test(
    'slicing',
    testRebufferSequence(
      [32, 32],
      {
        bufferSize: 16,
      },
      [16, 16, 16, 16]
    )
  )
  test(
    'jointing',
    testRebufferSequence(
      [32, 32],
      {
        bufferSize: 64,
      },
      [64]
    )
  )
  test(
    'slicing non-multiple',
    testRebufferSequence(
      [32],
      {
        bufferSize: 12,
      },
      [12, 12, 8]
    )
  )
  test(
    'jointing non-multiple',
    testRebufferSequence(
      [32, 32, 32, 32],
      {
        bufferSize: 47,
      },
      [47, 47, 34]
    )
  )
  test(
    'irregular input',
    testRebufferSequence(
      [32, 7, 32, 47, 32, 145],
      {
        bufferSize: 32,
      },
      [32, 32, 32, 32, 32, 32, 32, 32, 32, 7]
    )
  )
  test(
    'header',
    testRebufferSequence(
      [32, 32],
      {
        header: 12,
        bufferSize: 32,
      },
      [12, 32, 20]
    )
  )
  test(
    'header with just enough data on first buffer',
    testRebufferSequence(
      [12, 32],
      {
        header: 12,
        bufferSize: 32,
      },
      [12, 32]
    )
  )
  test(
    'header with not enough data on first buffer',
    testRebufferSequence(
      [8, 32],
      {
        header: 12,
        bufferSize: 32,
      },
      [12, 28]
    )
  )
  test(
    'header recomposition over multiple chunks',
    testRebufferSequence(
      [4, 4, 4, 4, 4, 4],
      {
        header: 12,
        bufferSize: 32,
      },
      [12, 12]
    )
  )
  test(
    'header only (recomposed)',
    testRebufferSequence(
      [4, 4, 4],
      {
        header: 12,
        bufferSize: 32,
      },
      [12]
    )
  )
  test(
    'header only (in one block)',
    testRebufferSequence(
      [12],
      {
        header: 12,
        bufferSize: 32,
      },
      [12]
    )
  )
  test(
    'not enough data for even just the header',
    testRebufferSequence(
      [4],
      {
        header: 12,
        bufferSize: 32,
      },
      [12, 12],
      true
    )
  )
  test(
    'header larger than subsequent blocks',
    testRebufferSequence(
      [32, 32],
      {
        header: 32,
        bufferSize: 8,
      },
      [32, 8, 8, 8, 8]
    )
  )
  test(
    'header equal to block size',
    testRebufferSequence(
      [32, 32],
      {
        header: 32,
        bufferSize: 32,
      },
      [32, 32]
    )
  )
})
