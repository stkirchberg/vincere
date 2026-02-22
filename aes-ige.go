package main

import (
	"crypto/hmac"
	"crypto/rand"
)

// --- AES PREREQUISITES ---
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var rsbox [256]byte

func init() {
	for i, b := range sbox {
		rsbox[b] = byte(i)
	}
}

func encryptFull(sharedSecret []byte, plaintext string) (string, error) {
	salt := make([]byte, 32)
	rand.Read(salt)

	key, iv := deriveKeys(sharedSecret, salt)

	paddedPlain := pad([]byte(plaintext))
	ciphertext, err := aesIgeEncrypt(key, iv, paddedPlain)
	if err != nil {
		return "", err
	}

	// HMAC with Salt + Ciphertext
	h := hmac.New(NewSHA256, key)
	h.Write(salt)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	// Paket: Salt(32) + MAC(32) + Ciphertext
	final := append(salt, append(mac, ciphertext...)...)
	return myHexEncode(final), nil
}

func decryptFull(sharedSecret []byte, hexData string) (string, error) {
	data, err := myHexDecode(hexData)
	if err != nil || len(data) < 65 { // 32 Salt + 32 MAC + min 1 block
		return "", myNewError("Format corrupt")
	}

	salt := data[:32]
	receivedMac := data[32:64]
	ciphertext := data[64:]

	key, iv := deriveKeys(sharedSecret, salt)

	h := hmac.New(NewSHA256, key)
	h.Write(salt)
	h.Write(ciphertext)
	expectedMac := h.Sum(nil)

	if !hmac.Equal(receivedMac, expectedMac) {
		return "", myNewError("Integritätsfehler")
	}

	decryptedPadded, err := aesIgeDecrypt(key, iv, ciphertext)
	if err != nil {
		return "", err
	}

	unpadded, err := unpad(decryptedPadded)
	if err != nil {
		return "", err
	}

	return string(unpadded), nil
}

// --- SECURE KEY DERIVATION ---

func deriveKeys(sharedSecret, salt []byte) (key, iv []byte) {
	hKey := hmac.New(NewSHA256, salt)
	hKey.Write(sharedSecret)
	hKey.Write([]byte("AES_KEY_GEN"))
	key = hKey.Sum(nil)

	hIv := hmac.New(NewSHA256, key)
	hIv.Write(salt)
	hIv.Write([]byte("IGE_IV_GEN"))
	iv = hIv.Sum(nil)

	return key, iv
}

// --- AES IGE CORE ---

func aesIgeEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	expanded := expandKey(key)
	ciphertext := make([]byte, len(plaintext))

	// IGE uses 32 Byte IV (16 for prevC, 16 for prevP)
	prevC := make([]byte, 16)
	prevP := make([]byte, 16)
	copy(prevC, iv[0:16])
	copy(prevP, iv[16:32])

	for i := 0; i < len(plaintext); i += 16 {
		chunk := make([]byte, 16)
		for j := 0; j < 16; j++ {
			chunk[j] = plaintext[i+j] ^ prevC[j]
		}

		res := encryptBlock(expanded, chunk)

		for j := 0; j < 16; j++ {
			ciphertext[i+j] = res[j] ^ prevP[j]
		}

		copy(prevC, ciphertext[i:i+16])
		copy(prevP, plaintext[i:i+16])
	}
	return ciphertext, nil
}

func aesIgeDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	expanded := expandKey(key)
	plaintext := make([]byte, len(ciphertext))

	prevC := make([]byte, 16)
	prevP := make([]byte, 16)
	copy(prevC, iv[0:16])
	copy(prevP, iv[16:32])

	for i := 0; i < len(ciphertext); i += 16 {
		chunk := make([]byte, 16)
		for j := 0; j < 16; j++ {
			chunk[j] = ciphertext[i+j] ^ prevP[j]
		}

		res := decryptBlock(expanded, chunk)

		for j := 0; j < 16; j++ {
			plaintext[i+j] = res[j] ^ prevC[j]
		}

		copy(prevP, plaintext[i:i+16])
		copy(prevC, ciphertext[i:i+16])
	}
	return plaintext, nil
}

// --- AES LOW LEVEL ---

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func expandKey(key []byte) []byte {
	w := make([]byte, 240)
	copy(w, key)
	rcon := []byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}
	for i := 32; i < 240; i += 4 {
		temp := make([]byte, 4)
		copy(temp, w[i-4:i])
		if i%32 == 0 {
			temp[0], temp[1], temp[2], temp[3] = sbox[temp[1]], sbox[temp[2]], sbox[temp[3]], sbox[temp[0]]
			temp[0] ^= rcon[(i/32)-1]
		} else if i%32 == 16 {
			for j := 0; j < 4; j++ {
				temp[j] = sbox[temp[j]]
			}
		}
		for j := 0; j < 4; j++ {
			w[i+j] = w[i-32+j] ^ temp[j]
		}
	}
	return w
}

func encryptBlock(expandedKey, block []byte) []byte {
	state := make([]byte, 16)
	copy(state, block)
	addRoundKey(state, expandedKey[0:16])
	for r := 1; r < 14; r++ {
		subBytes(state, sbox)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, expandedKey[r*16:(r+1)*16])
	}
	subBytes(state, sbox)
	shiftRows(state)
	addRoundKey(state, expandedKey[224:240])
	return state
}

func decryptBlock(expandedKey, block []byte) []byte {
	state := make([]byte, 16)
	copy(state, block)
	addRoundKey(state, expandedKey[224:240])
	for r := 13; r >= 1; r-- {
		invShiftRows(state)
		subBytes(state, rsbox)
		addRoundKey(state, expandedKey[r*16:(r+1)*16])
		invMixColumns(state)
	}
	invShiftRows(state)
	subBytes(state, rsbox)
	addRoundKey(state, expandedKey[0:16])
	return state
}

func addRoundKey(s, k []byte) {
	for i := 0; i < 16; i++ {
		s[i] ^= k[i]
	}
}
func subBytes(s []byte, box [256]byte) {
	for i := 0; i < 16; i++ {
		s[i] = box[s[i]]
	}
}
func shiftRows(s []byte) {
	s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
	s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
	s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
}
func invShiftRows(s []byte) {
	s[5], s[9], s[13], s[1] = s[1], s[5], s[9], s[13]
	s[10], s[14], s[2], s[6] = s[2], s[6], s[10], s[14]
	s[15], s[3], s[7], s[11] = s[3], s[7], s[11], s[15]
}
func mixColumns(s []byte) {
	for i := 0; i < 16; i += 4 {
		a, b, c, d := s[i], s[i+1], s[i+2], s[i+3]
		s[i] = gfMul(a, 2) ^ gfMul(b, 3) ^ c ^ d
		s[i+1] = a ^ gfMul(b, 2) ^ gfMul(c, 3) ^ d
		s[i+2] = a ^ b ^ gfMul(c, 2) ^ gfMul(d, 3)
		s[i+3] = gfMul(a, 3) ^ b ^ c ^ gfMul(d, 2)
	}
}
func invMixColumns(s []byte) {
	for i := 0; i < 16; i += 4 {
		a, b, c, d := s[i], s[i+1], s[i+2], s[i+3]
		s[i] = gfMul(a, 14) ^ gfMul(b, 11) ^ gfMul(c, 13) ^ gfMul(d, 9)
		s[i+1] = gfMul(a, 9) ^ gfMul(b, 14) ^ gfMul(c, 11) ^ gfMul(d, 13)
		s[i+2] = gfMul(a, 13) ^ gfMul(b, 9) ^ gfMul(c, 14) ^ gfMul(d, 11)
		s[i+3] = gfMul(a, 11) ^ gfMul(b, 13) ^ gfMul(c, 9) ^ gfMul(d, 14)
	}
}
func pad(d []byte) []byte {
	p := 16 - (len(d) % 16)
	padding := make([]byte, p)
	for i := range padding {
		padding[i] = byte(p)
	}
	return append(d, padding...)
}
func unpad(d []byte) ([]byte, error) {
	if len(d) == 0 {
		return d, nil
	}
	p := int(d[len(d)-1])
	if p > 16 || p == 0 || len(d) < p {
		return nil, myNewError("Padding Error")
	}
	return d[:len(d)-p], nil
}
