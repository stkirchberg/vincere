package main

func myConstantTimeCompare(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}

	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}

	return myConstantTimeByteEq(v, 0)
}

func myConstantTimeByteEq(x, y byte) int {
	z := ^(x ^ y)
	z &= z >> 4
	z &= z >> 2
	z &= z >> 1
	return int(z & 1)
}
