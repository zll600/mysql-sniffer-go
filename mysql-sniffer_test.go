package main

import (
	"reflect"
	"testing"
)

// ========== cleanupQuery Tests ==========

func cleanupHelper(t *testing.T, input, expected string) {
	var iv []byte = []byte(input)
	var out string = cleanupQuery(iv)
	if out != expected {
		t.Errorf("For query %s\n    Got %s\n    Expected %s", input, out, expected)
	}
}

func TestSimple(t *testing.T) {
	cleanupHelper(t, "select * from table where col=1",
		"select * from table where col=?")

	// Should these be ?? or ?
	cleanupHelper(t, "select * from table where col=\"hello\"", "select * from table where col=?")
	cleanupHelper(t, "select * from table where col='hello'", "select * from table where col=?")

	cleanupHelper(t, "select * from table where col='\\''", "select * from table where col=?")
}

func TestMultipleIn(t *testing.T) {
	cleanupHelper(t, "select * from table where x in (1, 2, 'foo')",
		"select * from table where x in (?)")
}

func TestWhitespace(t *testing.T) {
	cleanupHelper(t, "select *     from      table", "select * from table")
	cleanupHelper(t, "select *\nfrom\n\n\n\r\ntable", "select * from table")
}

func TestFailing(t *testing.T) {
	cleanupHelper(t, "select * from s2compiled", "select * from s2compiled")

	// Should these be ??, as above
	cleanupHelper(t, "select * from table where col=\"'\"", "select * from table where col=?")
	cleanupHelper(t, "select * from table where col='\"'", "select * from table where col=?")
}

func TestCleanupQueryWithNumbers(t *testing.T) {
	cleanupHelper(t, "select * from users where id=123", "select * from users where id=?")
	cleanupHelper(t, "select * from users where id=0", "select * from users where id=?")
	cleanupHelper(t, "select * from users where id=999999", "select * from users where id=?")
}

func TestCleanupQueryWithMultipleValues(t *testing.T) {
	cleanupHelper(t, "insert into users values (1, 'john', 'doe')",
		"insert into users values (?)")
	cleanupHelper(t, "update users set name='alice', age=25 where id=1",
		"update users set name=? age=? where id=?")
}

func TestCleanupQueryWithComments(t *testing.T) {
	cleanupHelper(t, "SELECT /* localhost:route1 */ * FROM users",
		"SELECT /* route1 */ * FROM users")
	cleanupHelper(t, "SELECT /* route2 */ * FROM users",
		"SELECT /* route2 */ * FROM users")
}

func TestCleanupQueryComplex(t *testing.T) {
	cleanupHelper(t,
		"select u.name, u.email from users u where u.id in (1, 2, 3) and u.status='active'",
		"select u.name u.email from users u where u.id in (?) and u.status=?")
}

// ========== scanToken Tests ==========

func TestScanTokenWord(t *testing.T) {
	tests := []struct {
		input         string
		wantLength    int
		wantTokenType int
	}{
		{"select", 6, TOKEN_WORD},
		{"SELECT", 6, TOKEN_WORD},
		{"table_name", 10, TOKEN_WORD},
		{"user$id", 7, TOKEN_WORD},
		{"col_1", 5, TOKEN_WORD},
		{"a", 1, TOKEN_WORD},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			length, tokenType := scanToken([]byte(tt.input))
			if length != tt.wantLength {
				t.Errorf("scanToken(%q) length = %d, want %d", tt.input, length, tt.wantLength)
			}
			if tokenType != tt.wantTokenType {
				t.Errorf("scanToken(%q) tokenType = %d, want %d", tt.input, tokenType, tt.wantTokenType)
			}
		})
	}
}

func TestScanTokenNumber(t *testing.T) {
	tests := []struct {
		input         string
		wantLength    int
		wantTokenType int
	}{
		{"123", 3, TOKEN_NUMBER},
		{"0", 1, TOKEN_NUMBER},
		{"999999", 6, TOKEN_NUMBER},
		{"42abc", 2, TOKEN_NUMBER}, // stops at 'a'
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			length, tokenType := scanToken([]byte(tt.input))
			if length != tt.wantLength {
				t.Errorf("scanToken(%q) length = %d, want %d", tt.input, length, tt.wantLength)
			}
			if tokenType != tt.wantTokenType {
				t.Errorf("scanToken(%q) tokenType = %d, want %d", tt.input, tokenType, tt.wantTokenType)
			}
		})
	}
}

func TestScanTokenQuote(t *testing.T) {
	tests := []struct {
		input         string
		wantLength    int
		wantTokenType int
	}{
		{"'hello'", 7, TOKEN_QUOTE},
		{"\"world\"", 7, TOKEN_QUOTE},
		{"'escaped\\'quote'", 16, TOKEN_QUOTE},
		{"'unterminated", 13, TOKEN_QUOTE},
		{"\"also unterminated", 18, TOKEN_QUOTE},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			length, tokenType := scanToken([]byte(tt.input))
			if length != tt.wantLength {
				t.Errorf("scanToken(%q) length = %d, want %d", tt.input, length, tt.wantLength)
			}
			if tokenType != tt.wantTokenType {
				t.Errorf("scanToken(%q) tokenType = %d, want %d", tt.input, tokenType, tt.wantTokenType)
			}
		})
	}
}

func TestScanTokenWhitespace(t *testing.T) {
	tests := []struct {
		input         string
		wantLength    int
		wantTokenType int
	}{
		{" ", 1, TOKEN_WHITESPACE},
		{"   ", 3, TOKEN_WHITESPACE},
		{"\t\t", 2, TOKEN_WHITESPACE},
		{"\n\r\n", 3, TOKEN_WHITESPACE},
		{"  abc", 2, TOKEN_WHITESPACE},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			length, tokenType := scanToken([]byte(tt.input))
			if length != tt.wantLength {
				t.Errorf("scanToken(%q) length = %d, want %d", tt.input, length, tt.wantLength)
			}
			if tokenType != tt.wantTokenType {
				t.Errorf("scanToken(%q) tokenType = %d, want %d", tt.input, tokenType, tt.wantTokenType)
			}
		})
	}
}

func TestScanTokenOther(t *testing.T) {
	tests := []struct {
		input         string
		wantLength    int
		wantTokenType int
	}{
		{"*", 1, TOKEN_OTHER},
		{"(", 1, TOKEN_OTHER},
		{")", 1, TOKEN_OTHER},
		{",", 1, TOKEN_OTHER},
		{"=", 1, TOKEN_OTHER},
		{";", 1, TOKEN_OTHER},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			length, tokenType := scanToken([]byte(tt.input))
			if length != tt.wantLength {
				t.Errorf("scanToken(%q) length = %d, want %d", tt.input, length, tt.wantLength)
			}
			if tokenType != tt.wantTokenType {
				t.Errorf("scanToken(%q) tokenType = %d, want %d", tt.input, tokenType, tt.wantTokenType)
			}
		})
	}
}

// ========== parseFormat Tests ==========

func TestParseFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []interface{}
	}{
		{
			name:     "query only",
			input:    "#q",
			expected: []interface{}{F_QUERY},
		},
		{
			name:     "source and query",
			input:    "#s:#q",
			expected: []interface{}{F_SOURCE, ":", F_QUERY},
		},
		{
			name:     "source ip and query",
			input:    "#i:#q",
			expected: []interface{}{F_SOURCEIP, ":", F_QUERY},
		},
		{
			name:     "route",
			input:    "#r",
			expected: []interface{}{F_ROUTE},
		},
		{
			name:     "complex format",
			input:    "[#s] #q",
			expected: []interface{}{"[", F_SOURCE, "] ", F_QUERY},
		},
		{
			name:     "escaped hash",
			input:    "##q",
			expected: []interface{}{"#q"},
		},
		{
			name:     "default empty",
			input:    "",
			expected: []any{F_SOURCEIP, ":", F_QUERY},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global format variable
			format = nil
			parseFormat(tt.input)

			if !reflect.DeepEqual(format, tt.expected) {
				t.Errorf("parseFormat(%q)\n  got:  %v\n  want: %v", tt.input, format, tt.expected)
			}
		})
	}
}

// ========== carvePacket Tests ==========
func TestCarvePacket(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantPtype   int
		wantDataLen int
		wantBufLen  int
	}{
		{
			name:        "empty buffer",
			input:       []byte{},
			wantPtype:   -1,
			wantDataLen: 0,
			wantBufLen:  0,
		},
		{
			name:        "buffer too small",
			input:       []byte{0x01, 0x00, 0x00},
			wantPtype:   -1,
			wantDataLen: 0,
			wantBufLen:  3,
		},
		{
			name: "valid query packet",
			// Packet: size=6 (0x06, 0x00, 0x00), seq=0, type=3 (COM_QUERY), data="hello"
			input:       []byte{0x06, 0x00, 0x00, 0x00, 0x03, 'h', 'e', 'l', 'l', 'o'},
			wantPtype:   COM_QUERY,
			wantDataLen: 5,
			wantBufLen:  0, // buffer should be consumed
		},
		{
			name: "valid packet with remaining data",
			// First packet + extra bytes
			input:       []byte{0x04, 0x00, 0x00, 0x00, 0x03, 'f', 'o', 'o', 0xFF, 0xFF},
			wantPtype:   COM_QUERY,
			wantDataLen: 3,
			wantBufLen:  2, // remaining bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, len(tt.input))
			copy(buf, tt.input)

			ptype, data := carvePacket(&buf)

			if ptype != tt.wantPtype {
				t.Errorf("carvePacket() ptype = %d, want %d", ptype, tt.wantPtype)
			}
			if len(data) != tt.wantDataLen {
				t.Errorf("carvePacket() data length = %d, want %d", len(data), tt.wantDataLen)
			}
			if len(buf) != tt.wantBufLen {
				t.Errorf("carvePacket() remaining buffer length = %d, want %d", len(buf), tt.wantBufLen)
			}
		})
	}
}

// ========== calculateTimes Tests ==========

func TestCalculateTimes(t *testing.T) {
	tests := []struct {
		name    string
		timings [TIME_BUCKETS]uint64
		wantMin float64
		wantAvg float64
		wantMax float64
	}{
		{
			name:    "all zeros",
			timings: [TIME_BUCKETS]uint64{},
			wantMin: 0.0,
			wantAvg: 0.0,
			wantMax: 0.0,
		},
		{
			name: "single value",
			timings: func() [TIME_BUCKETS]uint64 {
				var t [TIME_BUCKETS]uint64
				t[0] = 5000000 // 5ms in nanoseconds
				return t
			}(),
			wantMin: 5.0,
			wantAvg: 5.0,
			wantMax: 5.0,
		},
		{
			name: "multiple values",
			timings: func() [TIME_BUCKETS]uint64 {
				var t [TIME_BUCKETS]uint64
				t[0] = 1000000  // 1ms
				t[1] = 5000000  // 5ms
				t[2] = 10000000 // 10ms
				return t
			}(),
			wantMin: 1.0,
			wantAvg: 5.333333, // (1+5+10)/3 ≈ 5.33ms
			wantMax: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			min, avg, max := calculateTimes(&tt.timings)

			// Use approximate comparison for floating point
			if !floatEquals(min, tt.wantMin, 0.01) {
				t.Errorf("calculateTimes() min = %f, want %f", min, tt.wantMin)
			}
			if !floatEquals(avg, tt.wantAvg, 0.01) {
				t.Errorf("calculateTimes() avg = %f, want %f", avg, tt.wantAvg)
			}
			if !floatEquals(max, tt.wantMax, 0.01) {
				t.Errorf("calculateTimes() max = %f, want %f", max, tt.wantMax)
			}
		})
	}
}

func floatEquals(a, b, epsilon float64) bool {
	if a-b < epsilon && b-a < epsilon {
		return true
	}
	return false
}

// ========== sortableSlice Tests ==========

func TestSortableSliceLen(t *testing.T) {
	s := sortableSlice{
		{value: 1.0, line: "a"},
		{value: 2.0, line: "b"},
		{value: 3.0, line: "c"},
	}

	if s.Len() != 3 {
		t.Errorf("sortableSlice.Len() = %d, want 3", s.Len())
	}
}

func TestSortableSliceLess(t *testing.T) {
	s := sortableSlice{
		{value: 1.0, line: "a"},
		{value: 2.0, line: "b"},
	}

	if !s.Less(0, 1) {
		t.Error("sortableSlice.Less(0, 1) should be true (1.0 < 2.0)")
	}
	if s.Less(1, 0) {
		t.Error("sortableSlice.Less(1, 0) should be false (2.0 > 1.0)")
	}
}

func TestSortableSliceSwap(t *testing.T) {
	s := sortableSlice{
		{value: 1.0, line: "a"},
		{value: 2.0, line: "b"},
	}

	s.Swap(0, 1)

	if s[0].value != 2.0 || s[0].line != "b" {
		t.Errorf("After swap, s[0] = {%f, %s}, want {2.0, b}", s[0].value, s[0].line)
	}
	if s[1].value != 1.0 || s[1].line != "a" {
		t.Errorf("After swap, s[1] = {%f, %s}, want {1.0, a}", s[1].value, s[1].line)
	}
}
