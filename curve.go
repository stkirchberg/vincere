package main

import (
	"crypto/rand"
	"errors"
)

type fe [5]uint64

func cswap(choice uint64, a, b *fe) {
	mask := -(choice)
	for i := 0; i < 5; i++ {
		t := mask & (a[i] ^ b[i])
		a[i] ^= t
		b[i] ^= t
	}
}

func add(out, a, b *fe) {
	for i := 0; i < 5; i++ {
		out[i] = a[i] + b[i]
	}
}

func sub(out, a, b *fe) {
	for i := 0; i < 5; i++ {
		out[i] = (a[i] + 0x7ffffffffffffed) - b[i]
	}
}

func mul(out, a, b *fe) {
	var t [10]uint64
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			t[i+j] += a[i] * b[j]
		}
	}
	out[0] = t[0] + 38*t[5]
	out[1] = t[1] + 38*t[6]
	out[2] = t[2] + 38*t[7]
	out[3] = t[3] + 38*t[8]
	out[4] = t[4] + 38*t[9]
}

func invert(out, in *fe) {
	t := *in
	for i := 0; i < 254; i++ {
		mul(&t, &t, &t)
	}
	*out = t
}

func X25519(scalar, basePoint [32]byte) ([32]byte, error) {
	s := scalar
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64

	defer func() {
		for i := range s {
			s[i] = 0
		}
	}()

	x1 := decodeFE(basePoint)
	x2, z2 := fe{1}, fe{0}
	x3, z3 := x1, fe{1}
	a24 := fe{121665}

	for i := 254; i >= 0; i-- {
		bit := uint64((s[i/8] >> (i % 8)) & 1)
		cswap(bit, &x2, &x3)
		cswap(bit, &z2, &z3)

		var a, aa, b, bb, e, c, d, da, cb fe
		add(&a, &x2, &z2)
		mul(&aa, &a, &a)
		sub(&b, &x2, &z2)
		mul(&bb, &b, &b)
		sub(&e, &aa, &bb)
		add(&c, &x3, &z3)
		sub(&d, &x3, &z3)
		mul(&da, &d, &a)
		mul(&cb, &c, &b)

		add(&x3, &da, &cb)
		mul(&x3, &x3, &x3)
		sub(&z3, &da, &cb)
		mul(&z3, &z3, &z3)
		mul(&z3, &z3, &x1)

		mul(&x2, &aa, &bb)
		mul(&z2, &e, &a24)
		add(&z2, &z2, &aa)
		mul(&z2, &z2, &e)

		cswap(bit, &x2, &x3)
		cswap(bit, &z2, &z3)
	}

	var invZ fe
	invert(&invZ, &z2)
	mul(&x2, &x2, &invZ)
	res := encodeFE(x2)

	var zero [32]byte
	if myConstantTimeCompare(res[:], zero[:]) == 1 {
		return [32]byte{}, errors.New("low-order point")
	}
	return res, nil
}

func GenerateKeyPair() (priv, pub [32]byte) {
	if _, err := rand.Read(priv[:]); err != nil {
		panic(err)
	}
	var base [32]byte
	base[0] = 9
	pub, _ = X25519(priv, base)
	return priv, pub
}

func decodeFE(in [32]byte) fe {
	var out fe
	out[0] = readUint64LittleEndian(in[0:8]) & 0x7ffffffffffff
	out[1] = (readUint64LittleEndian(in[6:14]) >> 3) & 0x7ffffffffffff
	out[2] = (readUint64LittleEndian(in[12:20]) >> 6) & 0x7ffffffffffff
	out[3] = (readUint64LittleEndian(in[19:27]) >> 1) & 0x7ffffffffffff
	last := uint64(in[25]) | uint64(in[26])<<8 | uint64(in[27])<<16 |
		uint64(in[28])<<24 | uint64(in[29])<<32 | uint64(in[30])<<40 |
		uint64(in[31])<<48
	out[4] = (last >> 4) & 0x7ffffffffffff
	return out
}

func encodeFE(in fe) [32]byte {
	var out [32]byte
	putUint64LittleEndian(out[0:8], in[0]|(in[1]<<51))
	putUint64LittleEndian(out[8:16], (in[1]>>13)|(in[2]<<38))
	putUint64LittleEndian(out[16:24], (in[2]>>26)|(in[3]<<25))
	putUint64LittleEndian(out[24:32], (in[3]>>39)|(in[4]<<12))
	return out
}
