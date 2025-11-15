package main

import (
	"reflect"
	"testing"

	"github.com/go-mysql-org/go-mysql/mysql"
)

// ========== cleanupQuery Tests ==========

func cleanupHelper(t *testing.T, input, expected string) {
	iv := []byte(input)
	if out := cleanupQuery(iv); out != expected {
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
		wantErr     bool
		wantPtype   CommandType
		wantDataLen int
		wantBufLen  int
	}{
		{
			name:        "empty buffer",
			input:       []byte{},
			wantErr:     true,
			wantPtype:   0,
			wantDataLen: 0,
			wantBufLen:  0,
		},
		{
			name:        "buffer too small",
			input:       []byte{0x01, 0x00, 0x00},
			wantErr:     true,
			wantPtype:   0,
			wantDataLen: 0,
			wantBufLen:  3,
		},
		{
			name: "valid query packet",
			// Packet: size=6 (0x06, 0x00, 0x00), seq=0, type=3 (COM_QUERY), data="hello"
			input:       []byte{0x06, 0x00, 0x00, 0x00, 0x03, 'h', 'e', 'l', 'l', 'o'},
			wantErr:     false,
			wantPtype:   CommandType(mysql.COM_QUERY),
			wantDataLen: 5,
			wantBufLen:  0, // buffer should be consumed
		},
		{
			name: "valid packet with remaining data",
			// First packet + extra bytes
			input:       []byte{0x04, 0x00, 0x00, 0x00, 0x03, 'f', 'o', 'o', 0xFF, 0xFF},
			wantErr:     false,
			wantPtype:   CommandType(mysql.COM_QUERY),
			wantDataLen: 3,
			wantBufLen:  2, // remaining bytes
		},
		{
			name: "MySQL 8.0.23+ packet with query attributes",
			// Real packet: #\x00\x00\x00\x03\x00\x01select * from users where id = 1
			// Header: 0x23(35), 0x00, 0x00 (payload length) + 0x00 (sequence)
			// Payload: 0x03 (COM_QUERY) + 0x00 0x01 (query attributes) + query text
			input: append(
				[]byte{0x23, 0x00, 0x00, 0x00, 0x03},                                         // header + command
				append([]byte{0x00, 0x01}, []byte("select * from users where id = 1")...)..., // query attributes + query
			),
			wantErr:     false,
			wantPtype:   CommandType(mysql.COM_QUERY),
			wantDataLen: 34, // 2 bytes query attributes + 32 bytes query text
			wantBufLen:  0,  // buffer should be consumed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, len(tt.input))
			copy(buf, tt.input)

			ptype, data, err := carvePacket(&buf)

			if (err != nil) != tt.wantErr {
				t.Errorf("carvePacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if ptype != tt.wantPtype {
					t.Errorf("carvePacket() ptype = %v (%s), want %v (%s)", ptype, ptype.String(), tt.wantPtype, tt.wantPtype.String())
				}
				if len(data) != tt.wantDataLen {
					t.Errorf("carvePacket() data length = %d, want %d", len(data), tt.wantDataLen)
				}
				if len(buf) != tt.wantBufLen {
					t.Errorf("carvePacket() remaining buffer length = %d, want %d", len(buf), tt.wantBufLen)
				}
			}
		})
	}
}

// ========== parseComQuery Tests ==========

func TestParseComQuery(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantQuery string
		wantErr   bool
	}{
		{
			name:      "empty data",
			input:     []byte{},
			wantQuery: "",
			wantErr:   true,
		},
		{
			name:      "legacy format - simple SELECT",
			input:     []byte("select * from users"),
			wantQuery: "select * from users",
			wantErr:   false,
		},
		{
			name:      "legacy format - SELECT with number",
			input:     []byte("select * from users where id = 1"),
			wantQuery: "select * from users where id = 1",
			wantErr:   false,
		},
		{
			name:      "legacy format - INSERT",
			input:     []byte("insert into users values (1, 'john')"),
			wantQuery: "insert into users values (1, 'john')",
			wantErr:   false,
		},
		{
			name: "MySQL 8.0.23+ format - parameter_count=0, parameter_set_count=1",
			// Real packet from user: \x00\x01select * from users where id = 1
			input:     []byte{0x00, 0x01, 's', 'e', 'l', 'e', 'c', 't', ' ', '*', ' ', 'f', 'r', 'o', 'm', ' ', 'u', 's', 'e', 'r', 's', ' ', 'w', 'h', 'e', 'r', 'e', ' ', 'i', 'd', ' ', '=', ' ', '1'},
			wantQuery: "select * from users where id = 1",
			wantErr:   false,
		},
		{
			name: "MySQL 8.0.23+ format - parameter_count=0, parameter_set_count=1 (bytes)",
			// Using bytes literal for clarity
			input:     append([]byte{0x00, 0x01}, []byte("select * from users where id = 1")...),
			wantQuery: "select * from users where id = 1",
			wantErr:   false,
		},
		{
			name:      "MySQL 8.0.23+ format - different query",
			input:     append([]byte{0x00, 0x01}, []byte("UPDATE users SET name='alice' WHERE id=1")...),
			wantQuery: "UPDATE users SET name='alice' WHERE id=1",
			wantErr:   false,
		},
		{
			name:      "MySQL 8.0.23+ format - parameter_count=0, parameter_set_count=2",
			input:     append([]byte{0x00, 0x02}, []byte("select 1")...),
			wantQuery: "select 1",
			wantErr:   false,
		},
		{
			name:      "MySQL 8.0.23+ format - incomplete (only parameter_count)",
			input:     []byte{0x00},
			wantQuery: "",
			wantErr:   true,
		},
		{
			name:      "MySQL 8.0.23+ format - incomplete (no query text)",
			input:     []byte{0x00, 0x01},
			wantQuery: "",
			wantErr:   true,
		},
		{
			name:      "MySQL 8.0.23+ format - with parameters (not supported)",
			input:     append([]byte{0x01, 0x01}, []byte("select ?")...),
			wantQuery: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := parseComQuery(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseComQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if string(query) != tt.wantQuery {
					t.Errorf("parseComQuery() query = %q, want %q", string(query), tt.wantQuery)
				}
			}
		})
	}
}

// ========== MySQL Response Parsing Tests ==========

func TestParseResultSetResponse(t *testing.T) {
	// Real MySQL response packet for: select * from t1 where id = 1
	// This response contains 4 columns and 1 row of data
	// Database: lg, Table: t1
	responseData := []byte("\x01\x00\x00\x01\x04 \x00\x00\x02\x03def\x02lg\x02t1\x02t1\x02id\x02id\f?\x00\v\x00\x00\x00\x03\x03B\x00\x00\x00&\x00\x00\x03\x03def\x02lg\x02t1\x02t1\x05email\x05email\f\xff\x00\xfc\x03\x00\x00\xfd\x01\x10\x00\x00\x000\x00\x00\x04\x03def\x02lg\x02t1\x02t1\ncreated_at\ncreated_at\f?\x00\x13\x00\x00\x00\a\x81\x04\x00\x00\x000\x00\x00\x05\x03def\x02lg\x02t1\x02t1\nupdated_at\nupdated_at\f?\x00\x13\x00\x00\x00\a\x81$\x00\x00\x009\x00\x00\x06\x011\x0elg@example.com\x132025-11-14 21:48:48\x132025-11-14 21:48:48\a\x00\x00\a\xfe\x00\x00\"\x00\x00\x00")

	// Split response into individual packets
	packets := collectAllResponsePackets(responseData)

	if len(packets) < 2 {
		t.Fatalf("collectAllResponsePackets() returned %d packets, want at least 2", len(packets))
	}

	// First packet: column count
	columnCount, _, n := mysql.LengthEncodedInt(packets[0])
	if n == 0 || columnCount == 0 {
		t.Fatalf("Failed to parse column count from first packet")
	}

	// Verify column count
	expectedColumnCount := uint64(4)
	if columnCount != expectedColumnCount {
		t.Errorf("Column count = %d, want %d", columnCount, expectedColumnCount)
	}

	// Parse column names from field definition packets
	var columns []string
	for i := uint64(0); i < columnCount && int(i+1) < len(packets); i++ {
		pkt := packets[i+1]
		if len(pkt) > 0 && pkt[0] == 0xfe {
			break // EOF packet
		}
		colName := parseColumnDefinition(pkt)
		columns = append(columns, colName)
	}

	// Verify number of columns parsed
	if len(columns) != int(expectedColumnCount) {
		t.Errorf("Parsed %d columns, want %d", len(columns), expectedColumnCount)
	}

	// Verify column names
	expectedColumns := []string{
		"id", "email", "created_at", "updated_at",
	}
	for i, expectedCol := range expectedColumns {
		if i >= len(columns) {
			t.Errorf("Missing column at index %d, expected %s", i, expectedCol)
			continue
		}
		if columns[i] != expectedCol {
			t.Errorf("columns[%d] = %s, want %s", i, columns[i], expectedCol)
		}
	}

	// Find the row data packet
	// Packet structure: [0] = column count, [1..N] = column definitions, [N+1] = row data, [N+2] = EOF
	rowPacketIdx := int(columnCount) + 1 // Directly after column definitions

	if rowPacketIdx >= len(packets) {
		t.Fatalf("Row packet not found, expected at index %d but only have %d packets", rowPacketIdx, len(packets))
	}

	rowPacket := packets[rowPacketIdx]

	row := parseRowData(rowPacket, int(columnCount))

	// Verify number of values in the row
	if len(row) != int(expectedColumnCount) {
		t.Errorf("Row has %d values, want %d", len(row), expectedColumnCount)
	}

	// Verify specific values
	expectedValues := map[int]string{
		0: "1",                   // id
		1: "lg@example.com",      // email
		2: "2025-11-14 21:48:48", // created_at
		3: "2025-11-14 21:48:48", // updated_at
	}

	for idx, expectedVal := range expectedValues {
		if idx >= len(row) {
			t.Errorf("Missing value at index %d", idx)
			continue
		}
		if row[idx] != expectedVal {
			t.Errorf("row[%d] = %q, want %q", idx, row[idx], expectedVal)
		}
	}
}

func TestParseOKPacket(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		wantContains    []string // Strings that should be in the result
		wantNotContains []string // Strings that should NOT be in the result
	}{
		{
			name: "simple OK with no affected rows",
			// 0x00 = OK byte, followed by 0x00 (affected rows), 0x00 (last insert ID), status flags, warnings
			data:            []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantContains:    []string{"OK"},
			wantNotContains: []string{"row(s) affected", "last insert ID", "warning"},
		},
		{
			name: "OK with affected rows",
			// 0x00 = OK, 0x05 = 5 affected rows, 0x00 = no last insert ID
			data:            []byte{0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantContains:    []string{"OK", "5", "row(s) affected"},
			wantNotContains: []string{"last insert ID"},
		},
		{
			name: "OK with last insert ID",
			// 0x00 = OK, 0x00 = 0 affected rows, 0x0a = 10 as last insert ID
			data:            []byte{0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00},
			wantContains:    []string{"OK", "last insert ID", "10"},
			wantNotContains: []string{"row(s) affected"},
		},
		{
			name: "OK with warnings",
			// 0x00 = OK, 0x00 = 0 affected, 0x00 = 0 insert ID, 0x00 0x00 = status, 0x02 0x00 = 2 warnings
			data:         []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00},
			wantContains: []string{"OK", "2", "warning"},
		},
		{
			name: "OK with all fields",
			// 3 affected rows, last insert ID 100, 1 warning
			data:         []byte{0x00, 0x03, 0x64, 0x00, 0x00, 0x01, 0x00},
			wantContains: []string{"OK", "3", "row(s) affected", "100", "last insert ID", "1", "warning"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOKPacket(tt.data)

			for _, want := range tt.wantContains {
				if !contains(result, want) {
					t.Errorf("parseOKPacket() result should contain %q, got: %s", want, result)
				}
			}

			for _, notWant := range tt.wantNotContains {
				if contains(result, notWant) {
					t.Errorf("parseOKPacket() result should NOT contain %q, got: %s", notWant, result)
				}
			}
		})
	}
}

func TestParseErrorPacket(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		wantContains []string
	}{
		{
			name: "simple error without SQL state",
			// 0xff = ERROR byte, 0x10 0x04 = error code 1040, message
			data:         []byte{0xff, 0x10, 0x04, 'T', 'o', 'o', ' ', 'm', 'a', 'n', 'y', ' ', 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', 's'},
			wantContains: []string{"ERROR", "1040", "Too many connections"},
		},
		{
			name: "error with SQL state",
			// 0xff = ERROR, 0x15 0x04 = error code 1045, '#' = SQL state marker, "28000" = SQL state, message
			data:         append([]byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}, []byte("Access denied for user")...),
			wantContains: []string{"ERROR", "1045", "28000", "Access denied for user"},
		},
		{
			name: "table doesn't exist error",
			// 0xff = ERROR, 0x46 0x04 = error code 1110 (actually 1146), '#' = SQL state marker, "42S02", message
			data:         append([]byte{0xff, 0x7a, 0x04, '#', '4', '2', 'S', '0', '2'}, []byte("Table 'test.users' doesn't exist")...),
			wantContains: []string{"ERROR", "1146", "42S02", "Table", "doesn't exist"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseErrorPacket(tt.data)

			for _, want := range tt.wantContains {
				if !contains(result, want) {
					t.Errorf("parseErrorPacket() result should contain %q, got: %s", want, result)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring (case-insensitive would be better, but exact match is fine for tests)
func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
