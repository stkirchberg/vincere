package main

import (
	"crypto/rand"
	"math/big"
)

var (
	// P = 2^255 - 19
	curveP, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	// A24 = (A - 2) / 4 = (486662 - 2) / 4 = 121665
	curveA24 = big.NewInt(121665)
)

func X25519(scalar, basePoint [32]byte) [32]byte {

	sBytes := scalar
	sBytes[0] &= 248
	sBytes[31] &= 127
	sBytes[31] |= 64
	s := leBytesToBigInt(sBytes[:])

	u := leBytesToBigInt(basePoint[:])

	x1 := u
	x2 := big.NewInt(1)
	z2 := big.NewInt(0)
	x3 := u
	z3 := big.NewInt(1)

	for i := 254; i >= 0; i-- {
		bit := s.Bit(i)

		if bit == 1 {
			x2, x3 = x3, x2
			z2, z3 = z3, z2
		}

		tA := new(big.Int).Add(x2, z2)
		tA.Mod(tA, curveP)
		aa := new(big.Int).Mul(tA, tA)
		aa.Mod(aa, curveP)

		tB := new(big.Int).Sub(x2, z2)
		tB.Mod(tB, curveP)
		bb := new(big.Int).Mul(tB, tB)
		bb.Mod(bb, curveP)

		e := new(big.Int).Sub(aa, bb)
		e.Mod(e, curveP)

		tC := new(big.Int).Add(x3, z3)
		tC.Mod(tC, curveP)

		tD := new(big.Int).Sub(x3, z3)
		tD.Mod(tD, curveP)

		da := new(big.Int).Mul(tD, tA)
		da.Mod(da, curveP)

		cb := new(big.Int).Mul(tC, tB)
		cb.Mod(cb, curveP)

		// Update x3, z3
		x3 = new(big.Int).Add(da, cb)
		x3.Mul(x3, x3)
		x3.Mod(x3, curveP)

		z3 = new(big.Int).Sub(da, cb)
		z3.Mul(z3, z3)
		z3.Mul(z3, x1)
		z3.Mod(z3, curveP)

		// Update x2, z2
		x2 = new(big.Int).Mul(aa, bb)
		x2.Mod(x2, curveP)

		tmpZ := new(big.Int).Mul(e, curveA24)
		tmpZ.Add(tmpZ, aa)
		tmpZ.Mul(tmpZ, e)
		z2.Mod(tmpZ, curveP)

		if bit == 1 {
			x2, x3 = x3, x2
			z2, z3 = z3, z2
		}
	}

	// x / z mod P
	res := new(big.Int).Mul(x2, z2.ModInverse(z2, curveP))
	res.Mod(res, curveP)

	return bigIntToLeBytes(res)
}

// new KeyPair
func GenerateKeyPair() (priv, pub [32]byte) {
	rand.Read(priv[:])

	// G = 9
	var base [32]byte
	base[0] = 9

	pub = X25519(priv, base)
	return priv, pub
}

// Little-Endian Convert
func leBytesToBigInt(b []byte) *big.Int {
	rev := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rev[i] = b[31-i]
	}
	return new(big.Int).SetBytes(rev)
}

func bigIntToLeBytes(n *big.Int) [32]byte {
	buf := n.Bytes()
	var res [32]byte
	for i := 0; i < len(buf) && i < 32; i++ {
		res[i] = buf[len(buf)-1-i]
	}
	return res
}
