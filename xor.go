package stun

func XOR(a, b []byte) []byte {
	n := len(a)
	if len(a) > len(b) {
		n = len(b)
	}

	buff := make([]byte, n)
	for i := 0; i < n; i++ {
		buff[i] = a[i] ^ b[i]
	}
	return buff
}
