package main

func myTrimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] <= ' ' {
		start++
	}
	for end > start && s[end-1] <= ' ' {
		end--
	}
	return s[start:end]
}

func myHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[0:len(prefix)] == prefix
}

func myTrimPrefix(s, prefix string) string {
	if myHasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}

func myContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func myJoin(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	res := elems[0]
	for _, s := range elems[1:] {
		res += sep + s
	}
	return res
}

func mySplitN(s, sep string, n int) []string {
	if n == 1 {
		return []string{s}
	}
	var res []string
	for i := 0; i < len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			res = append(res, s[:i])
			s = s[i+len(sep):]
			if len(res)+1 == n {
				break
			}
			i = -1
		}
	}
	res = append(res, s)
	return res
}
