'use strict'

var Buffer = require('safe-buffer').Buffer
var incr32 = require('../incr32')

var blockSize = 16

exports.encrypt = function (self, chunk) {
  var len = chunk.length
  var chunkNum = Math.ceil(len / blockSize)
  var start = self._cache.length
  var out = new Uint32Array(chunkNum * 4)
  var ivLen = 0
  var iv = self._prev

  for (var i = 0; i < chunkNum; i++) {
    self._cipher.encryptBlockRaw(out.subarray(i * 4, (i+1) * 4), self._prev)

    // incr32 inlined
    ivLen = iv.length
    while (ivLen--) {
      if (iv[ivLen] === 255) {
        iv[ivLen] = 0
      } else {
        iv[ivLen]++
        break
      }
    }
  }

  self._cache = Buffer.concat([ self._cache, toBuffer(out) ])
  xor(self._cache, chunk)

  var result = self._cache.slice(0, len)
  // update cache
  self._cache = self._cache.slice(len)

  return result
}

function xor(a, b) {
  for (var i = 0; i < a.length; i++) {
    a[i] = a[i] ^ b[i]
  }
}

function toBuffer(tarray)  {
  var out = Buffer.allocUnsafe(tarray.length*4)
  for (var i = 0; i < tarray.length; i++) {
    out.writeUInt32BE(tarray[i], i * 4)
  }
  return out
}
