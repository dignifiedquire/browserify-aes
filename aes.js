// based on the aes implimentation in triple sec
// https://github.com/keybase/triplesec
// which is in turn based on the one from crypto-js
// https://code.google.com/p/crypto-js/

var Buffer = require('safe-buffer').Buffer

function asUInt32Array (buf) {
  var len = (buf.length / 4) | 0
  var out = new Uint32Array(len)

  for (var i = 0; i < len; i++) {
    out[i] = buf.readUInt32BE(i * 4)
  }

  return out
}

function cryptBlock (M, keySchedule, SUB_MIX0, SUB_MIX1, SUB_MIX2, SUB_MIX3, SBOX, nRounds, t) {
  var s0 = M[0] ^ keySchedule[0]
  var s1 = M[1] ^ keySchedule[1]
  var s2 = M[2] ^ keySchedule[2]
  var s3 = M[3] ^ keySchedule[3]
  var t0, t1, t2, t3 = 0
  var ksRow = 4
  var round = 1

  for (; round < nRounds; round++) {
    t0 = SUB_MIX0[s0 >>> 24] ^
      SUB_MIX1[(s1 >>> 16) & 0xff] ^
      SUB_MIX2[(s2 >>> 8) & 0xff] ^
      SUB_MIX3[s3 & 0xff] ^
      keySchedule[ksRow]
    t1 = SUB_MIX0[s1 >>> 24] ^
      SUB_MIX1[(s2 >>> 16) & 0xff] ^
      SUB_MIX2[(s3 >>> 8) & 0xff] ^
      SUB_MIX3[s0 & 0xff] ^
      keySchedule[ksRow+1]
    t2 = SUB_MIX0[s2 >>> 24] ^
      SUB_MIX1[(s3 >>> 16) & 0xff] ^
      SUB_MIX2[(s0 >>> 8) & 0xff] ^
      SUB_MIX3[s1 & 0xff] ^
      keySchedule[ksRow+2]
    t3 = SUB_MIX0[s3 >>> 24] ^
      SUB_MIX1[(s0 >>> 16) & 0xff] ^
      SUB_MIX2[(s1 >>> 8) & 0xff] ^
      SUB_MIX3[s2 & 0xff] ^
      keySchedule[ksRow+3]
    s0 = t0
    s1 = t1
    s2 = t2
    s3 = t3
    ksRow += 4
  }

  t0 = ((SBOX[s0 >>> 24] << 24) |
        (SBOX[(s1 >>> 16) & 0xff] << 16) |
        (SBOX[(s2 >>> 8) & 0xff] << 8) |
        SBOX[s3 & 0xff]) ^
    keySchedule[ksRow++]
  t1 = ((SBOX[s1 >>> 24] << 24) |
        (SBOX[(s2 >>> 16) & 0xff] << 16) |
        (SBOX[(s3 >>> 8) & 0xff] << 8) |
        SBOX[s0 & 0xff]) ^
    keySchedule[ksRow++]
  t2 = ((SBOX[s2 >>> 24] << 24) |
        (SBOX[(s3 >>> 16) & 0xff] << 16) |
        (SBOX[(s0 >>> 8) & 0xff] << 8) |
        SBOX[s1 & 0xff]) ^
    keySchedule[ksRow++]
  t3 = ((SBOX[s3 >>> 24] << 24) |
        (SBOX[(s0 >>> 16) & 0xff] << 16) |
        (SBOX[(s1 >>> 8) & 0xff] << 8) |
        SBOX[s2 & 0xff]) ^
    keySchedule[ksRow++]

  t[0] = t0
  t[1] = t1
  t[2] = t2
  t[3] = t3
}

// AES constants
var RCON = new Uint32Array([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])
var G = (function () {
  // Compute double table
  var d = new Uint32Array(256)
  for (var j = 0; j < 256; j++) {
    if (j < 128) {
      d[j] = j << 1
    } else {
      d[j] = (j << 1) ^ 0x11b
    }
  }

  var SBOX = new Uint32Array(256)
  var INV_SBOX = new Uint32Array(256)
  var SUB_MIX = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)]
  var INV_SUB_MIX = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)]

  // Walk GF(2^8)
  var x = 0
  var xi = 0
  for (var i = 0; i < 256; ++i) {
    // Compute sbox
    var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4)
    sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63
    SBOX[x] = sx
    INV_SBOX[sx] = x

    // Compute multiplication
    var x2 = d[x]
    var x4 = d[x2]
    var x8 = d[x4]

    // Compute sub bytes, mix columns tables
    var t = (d[sx] * 0x101) ^ (sx * 0x1010100)
    SUB_MIX[0][x] = (t << 24) | (t >>> 8)
    SUB_MIX[1][x] = (t << 16) | (t >>> 16)
    SUB_MIX[2][x] = (t << 8) | (t >>> 24)
    SUB_MIX[3][x] = t

    // Compute inv sub bytes, inv mix columns tables
    t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100)
    INV_SUB_MIX[0][sx] = (t << 24) | (t >>> 8)
    INV_SUB_MIX[1][sx] = (t << 16) | (t >>> 16)
    INV_SUB_MIX[2][sx] = (t << 8) | (t >>> 24)
    INV_SUB_MIX[3][sx] = t

    if (x === 0) {
      x = xi = 1
    } else {
      x = x2 ^ d[d[d[x8 ^ x2]]]
      xi ^= d[d[xi]]
    }
  }

  return {
    SBOX: SBOX,
    INV_SBOX: INV_SBOX,
    SUB_MIX0: SUB_MIX[0],
    SUB_MIX1: SUB_MIX[1],
    SUB_MIX2: SUB_MIX[2],
    SUB_MIX3: SUB_MIX[3],
    INV_SUB_MIX0: INV_SUB_MIX[0],
    INV_SUB_MIX1: INV_SUB_MIX[1],
    INV_SUB_MIX2: INV_SUB_MIX[2],
    INV_SUB_MIX3: INV_SUB_MIX[3]
  }
})()

function AES (key) {
  this._key = asUInt32Array(key)
  this._reset()
}

AES.blockSize = 4 * 4
AES.keySize = 256 / 8
AES.prototype.blockSize = AES.blockSize
AES.prototype.keySize = AES.keySize
AES.prototype._reset = function () {
  var keyWords = this._key
  var keySize = keyWords.length
  var nRounds = keySize + 6
  var ksRows = (nRounds + 1) * 4

  this._nRounds = nRounds
  if (!this._keySchedule) {
    this._keySchedule = new Uint32Array(ksRows)
    this._invKeySchedule = new Uint32Array(ksRows)
  }

  for (var k = 0; k < keySize; k++) {
    this._keySchedule[k] = keyWords[k]
  }

  for (k = keySize; k < ksRows; k++) {
    var t = this._keySchedule[k - 1]

    var m = k % keySize
    if (m === 0) {
      t = (t << 8) | (t >>> 24)
      t =
        (G.SBOX[t >>> 24] << 24) |
        (G.SBOX[(t >>> 16) & 0xff] << 16) |
        (G.SBOX[(t >>> 8) & 0xff] << 8) |
        (G.SBOX[t & 0xff])

      t ^= RCON[(k / keySize) | 0] << 24
    } else if (keySize > 6 && m === 4) {
      t =
        (G.SBOX[t >>> 24] << 24) |
        (G.SBOX[(t >>> 16) & 0xff] << 16) |
        (G.SBOX[(t >>> 8) & 0xff] << 8) |
        (G.SBOX[t & 0xff])
    }

    this._keySchedule[k] = this._keySchedule[k - keySize] ^ t
  }

  for (var ik = 0; ik < ksRows; ik++) {
    var ksR = ksRows - ik
    var tt = this._keySchedule[ksR - (ik % 4 ? 0 : 4)]

    if (ik < 4 || ksR <= 4) {
      this._invKeySchedule[ik] = tt
    } else {
      this._invKeySchedule[ik] =
        G.INV_SUB_MIX0[G.SBOX[tt >>> 24]] ^
        G.INV_SUB_MIX1[G.SBOX[(tt >>> 16) & 0xff]] ^
        G.INV_SUB_MIX2[G.SBOX[(tt >>> 8) & 0xff]] ^
        G.INV_SUB_MIX3[G.SBOX[tt & 0xff]]
    }
  }
}

AES.prototype.encryptBlockRaw = function (out, M) {
  M = asUInt32Array(M)
  return cryptBlock(M, this._keySchedule, G.SUB_MIX0, G.SUB_MIX1, G.SUB_MIX2, G.SUB_MIX3, G.SBOX, this._nRounds, out)
}

AES.prototype.encryptBlock = function (M) {
  var out = new Uint32Array(4)
  this.encryptBlockRaw(out, M)
  var buf = Buffer.allocUnsafe(16)
  buf.writeUInt32BE(out[0], 0)
  buf.writeUInt32BE(out[1], 4)
  buf.writeUInt32BE(out[2], 8)
  buf.writeUInt32BE(out[3], 12)
  return buf
}

AES.prototype.decryptBlock = function (M) {
  M = asUInt32Array(M)

  // swap
  var m1 = M[1]
  M[1] = M[3]
  M[3] = m1

  var out = new Uint32Array(4)
  cryptBlock(M, this._invKeySchedule, G.INV_SUB_MIX0, G.INV_SUB_MIX1, G.INV_SUB_MIX2, G.INV_SUB_MIX3, G.INV_SBOX, this._nRounds, out)
  var buf = Buffer.allocUnsafe(16)
  buf.writeUInt32BE(out[0], 0)
  buf.writeUInt32BE(out[3], 4)
  buf.writeUInt32BE(out[2], 8)
  buf.writeUInt32BE(out[1], 12)
  return buf
}

AES.prototype.scrub = function () {
  this._keySchedule.fill(0)
  this._invKeySchedule.fill(0)
  this._key.fill(0)
}

module.exports.AES = AES
