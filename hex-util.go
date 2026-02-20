package main

func myHexEncode(src []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(src)*2)
	for i, v := range src {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}

func myHexDecode(s string) ([]byte, error) {
	src := []byte(s)
	dst := make([]byte, len(src)/2)
	for i := 0; i < len(dst); i++ {
		var res byte
		for j := 0; j < 2; j++ {
			var b byte
			c := src[i*2+j]
			switch {
			case '0' <= c && c <= '9':
				b = c - '0'
			case 'a' <= c && c <= 'f':
				b = c - 'a' + 10
			case 'A' <= c && c <= 'F':
				b = c - 'A' + 10
			}
			if j == 0 {
				res = b << 4
			} else {
				res |= b
			}
		}
		dst[i] = res
	}
	return dst, nil
}
