package main

import (
	"hash"
)

const (
	BlockSize = 64
	Size      = 32
)

type Digest struct {
	h   [8]uint32
	x   [BlockSize]byte
	nx  int
	len uint64
}

func rotr32(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

func NewSHA256() hash.Hash {
	d := new(Digest)
	d.Reset()
	return d
}

func (d *Digest) Reset() {
	d.h = [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	for i := range d.x {
		d.x[i] = 0
	}
	d.nx = 0
	d.len = 0
}

func (d *Digest) Zero() {
	for i := range d.h {
		d.h[i] = 0
	}
	for i := range d.x {
		d.x[i] = 0
	}
	d.nx = 0
	d.len = 0
}

func (d *Digest) Size() int      { return Size }
func (d *Digest) BlockSize() int { return BlockSize }

func (d *Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return nn, nil
}

func (d *Digest) Sum(in []byte) []byte {
	tmp := *d
	hashVal := tmp.checkSum()
	tmp.Zero()
	return append(in, hashVal[:]...)
}

func (d *Digest) checkSum() [Size]byte {
	lenInBytes := d.len
	padding := [128]byte{}
	padding[0] = 0x80

	var padLen int
	if lenInBytes%64 < 56 {
		padLen = int(56 - lenInBytes%64)
	} else {
		padLen = int(120 - lenInBytes%64)
	}
	d.Write(padding[:padLen])

	lo := lenInBytes << 3
	putUint64BigEndian(padding[:8], lo)
	d.Write(padding[:8])

	var digest [Size]byte
	for i, s := range d.h {
		putUint32BigEndian(digest[i*4:], s)
	}
	return digest
}

func block(d *Digest, p []byte) {
	var w [64]uint32
	for len(p) >= BlockSize {
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = readUint32BigEndian(p[j : j+4])
		}
		for i := 16; i < 64; i++ {
			v15 := w[i-15]
			s0 := rotr32(v15, 7) ^ rotr32(v15, 18) ^ (v15 >> 3)
			v2 := w[i-2]
			s1 := rotr32(v2, 17) ^ rotr32(v2, 19) ^ (v2 >> 10)
			w[i] = s1 + w[i-7] + s0 + w[i-16]
		}

		a, b, c, dVal, e, f, g, h := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]

		for i := 0; i < 64; i++ {
			s1 := rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
			ch := (e & f) ^ (^e & g)
			t1 := h + s1 + ch + _K[i] + w[i]
			s0 := rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			t2 := s0 + maj

			h, g, f, e = g, f, e, dVal+t1
			dVal, c, b, a = c, b, a, t1+t2
		}

		d.h[0] += a
		d.h[1] += b
		d.h[2] += c
		d.h[3] += dVal
		d.h[4] += e
		d.h[5] += f
		d.h[6] += g
		d.h[7] += h
		p = p[BlockSize:]
	}
	for i := range w {
		w[i] = 0
	}
}

type hmacHash struct {
	opad, ipad [BlockSize]byte
	inner      hash.Hash
	outer      hash.Hash
}

func (h *hmacHash) Zero() {
	for i := range h.ipad {
		h.ipad[i] = 0
		h.opad[i] = 0
	}
	if d, ok := h.inner.(*Digest); ok {
		d.Zero()
	}
	if d, ok := h.outer.(*Digest); ok {
		d.Zero()
	}
}

func NewHMAC(key []byte) hash.Hash {
	h := &hmacHash{
		inner: NewSHA256(),
		outer: NewSHA256(),
	}
	if len(key) > BlockSize {
		sum := NewSHA256()
		sum.Write(key)
		hashedKey := sum.Sum(nil)
		key = hashedKey
		if d, ok := sum.(*Digest); ok {
			d.Zero()
		}
		defer func() {
			for i := range hashedKey {
				hashedKey[i] = 0
			}
		}()
	}
	copy(h.ipad[:], key)
	copy(h.opad[:], key)
	for i := range h.ipad {
		h.ipad[i] ^= 0x36
		h.opad[i] ^= 0x5c
	}
	h.inner.Write(h.ipad[:])
	return h
}

func (h *hmacHash) Write(p []byte) (int, error) { return h.inner.Write(p) }
func (h *hmacHash) Size() int                   { return Size }
func (h *hmacHash) BlockSize() int              { return BlockSize }
func (h *hmacHash) Reset() {
	h.inner.Reset()
	h.inner.Write(h.ipad[:])
}

func (h *hmacHash) Sum(in []byte) []byte {
	innerSum := h.inner.Sum(nil)
	h.outer.Reset()
	h.outer.Write(h.opad[:])
	h.outer.Write(innerSum)
	res := h.outer.Sum(in)
	for i := range innerSum {
		innerSum[i] = 0
	}
	return res
}

func CheckMAC(message, messageMAC, key []byte) bool {
	h := NewHMAC(key)
	h.Write(message)
	expectedMAC := h.Sum(nil)
	return myConstantTimeCompare(expectedMAC, messageMAC) == 1
}

var _K = []uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
