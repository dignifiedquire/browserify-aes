'use strict'

function incr32 (iv) {
  var len = iv.length
  while (len--) {
    if (iv[len] === 255) {
      iv[len] = 0
    } else {
      iv[len]++
      break
    }
  }
}

module.exports = incr32
