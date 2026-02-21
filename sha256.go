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
	return append(in, hashVal[:]...)
}

func (d *Digest) checkSum() [Size]byte {
	l := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if l%64 < 56 {
		d.Write(tmp[0 : 56-l%64])
	} else {
		d.Write(tmp[0 : 120-l%64])
	}

	t := l << 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(t >> (56 - i*8))
	}
	d.Write(tmp[0:8])

	var digest [Size]byte
	for i, s := range d.h {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}
	return digest
}

func block(d *Digest, p []byte) {
	var w [64]uint32
	for len(p) >= BlockSize {
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
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
