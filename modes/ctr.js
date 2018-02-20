'use strict'

var Buffer = require('safe-buffer').Buffer
var incr32 = require('../incr32')

var blockSize = 16

exports.encrypt = function (self, chunk) {
  var len = chunk.length
  var chunkNum = Math.ceil(len / blockSize)
  var start = self._cache.length

  self._cache = Buffer.concat([
    self._cache,
    Buffer.allocUnsafe(chunkNum * blockSize)
  ])

  var offset, i
  var out = new Uint32Array(4)
  for (i = 0; i < chunkNum; i++) {
    self._cipher.encryptBlockRaw(out, self._prev)
    incr32(self._prev)

    offset = start + i * blockSize
    self._cache.writeUInt32BE(out[0], offset + 0)
    self._cache.writeUInt32BE(out[1], offset + 4)
    self._cache.writeUInt32BE(out[2], offset + 8)
    self._cache.writeUInt32BE(out[3], offset + 12)
  }

  // xor
  for (i = 0; i < len; i++) {
    self._cache[i] = chunk[i] ^ self._cache[i]
  }

  var result = self._cache.slice(0, len)
  // update cache
  self._cache = self._cache.slice(len)

  return result
}
