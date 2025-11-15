package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/go-mysql-org/go-mysql/mysql"
)

// MySQL packet types for responses
const (
	MYSQL_OK_PACKET  = 0x00
	MYSQL_EOF_PACKET = 0xfe
	MYSQL_ERR_PACKET = 0xff
)

// parseOKPacket parses a MySQL OK packet
func parseOKPacket(data []byte) string {
	if len(data) < 7 {
		return "OK"
	}

	pos := 1 // Skip the OK byte
	affectedRows, _, n := mysql.LengthEncodedInt(data[pos:])
	pos += n
	lastInsertID, _, n := mysql.LengthEncodedInt(data[pos:])
	pos += n

	var warnings uint16
	if len(data) >= pos+4 {
		_ = uint16(data[pos]) | uint16(data[pos+1])<<8 // statusFlags - unused for now
		pos += 2
		warnings = uint16(data[pos]) | uint16(data[pos+1])<<8
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("%sOK%s", COLOR_GREEN, COLOR_DEFAULT))

	if affectedRows > 0 {
		result.WriteString(fmt.Sprintf(", %s%d row(s) affected%s", COLOR_YELLOW, affectedRows, COLOR_DEFAULT))
	}
	if lastInsertID > 0 {
		result.WriteString(fmt.Sprintf(", %slast insert ID: %d%s", COLOR_CYAN, lastInsertID, COLOR_DEFAULT))
	}
	if warnings > 0 {
		result.WriteString(fmt.Sprintf(", %s%d warning(s)%s", COLOR_YELLOW, warnings, COLOR_DEFAULT))
	}

	return result.String()
}

// parseErrorPacket parses a MySQL ERROR packet
func parseErrorPacket(data []byte) string {
	if len(data) < 9 {
		return "ERROR"
	}

	pos := 1 // Skip the error byte
	errorCode := uint16(data[pos]) | uint16(data[pos+1])<<8
	pos += 2

	var sqlState string
	var message string

	// Check for SQL state marker '#'
	if data[pos] == '#' {
		pos++
		sqlState = string(data[pos : pos+5])
		pos += 5
		message = string(data[pos:])
	} else {
		message = string(data[pos:])
	}

	if sqlState != "" {
		return fmt.Sprintf("%sERROR %d (%s): %s%s", COLOR_RED, errorCode, sqlState, message, COLOR_DEFAULT)
	}
	return fmt.Sprintf("%sERROR %d: %s%s", COLOR_RED, errorCode, message, COLOR_DEFAULT)
}

// parseResultSetPacket parses a MySQL result set and returns all rows
func parseResultSetPacket(data []byte, showRows bool) string {
	if len(data) < 1 {
		return "Empty result set"
	}

	// First packet contains column count
	columnCount, _, n := mysql.LengthEncodedInt(data)
	if n == 0 || columnCount == 0 {
		return "Result set with 0 columns"
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("%sResultSet: %d column(s)%s", COLOR_GREEN, columnCount, COLOR_DEFAULT))

	return result.String()
}

// parseResultSetFull parses complete result set including field definitions and rows
func parseResultSetFull(packets [][]byte, showRows bool) string {
	if len(packets) < 2 {
		return "Incomplete result set"
	}

	var result strings.Builder

	// First packet: column count
	columnCount, _, n := mysql.LengthEncodedInt(packets[0])
	if n == 0 || columnCount == 0 {
		return "Result set with 0 columns"
	}

	// Parse column definitions
	var columns []string
	pktIdx := 1
	for i := uint64(0); i < columnCount && pktIdx < len(packets); i++ {
		pkt := packets[pktIdx]
		if len(pkt) > 0 && pkt[0] == MYSQL_EOF_PACKET {
			break
		}

		colName := parseColumnDefinition(pkt)
		columns = append(columns, colName)
		pktIdx++
	}

	result.WriteString(fmt.Sprintf("%sResultSet: %d column(s)%s", COLOR_GREEN, columnCount, COLOR_DEFAULT))

	if len(columns) > 0 {
		result.WriteString(fmt.Sprintf(" [%s%s%s]", COLOR_CYAN, strings.Join(columns, ", "), COLOR_DEFAULT))
	}

	// Skip EOF packet after column definitions (MySQL < 5.7 or when CLIENT_DEPRECATE_EOF not set)
	if pktIdx < len(packets) && len(packets[pktIdx]) > 0 && packets[pktIdx][0] == MYSQL_EOF_PACKET {
		pktIdx++
	}

	// Parse row data if requested
	if showRows {
		rowCount := 0
		result.WriteString("\n")

		for pktIdx < len(packets) {
			pkt := packets[pktIdx]
			if len(pkt) == 0 {
				pktIdx++
				continue
			}

			// Check for EOF packet (end of rows)
			if pkt[0] == MYSQL_EOF_PACKET {
				break
			}

			// Check for ERROR packet
			if pkt[0] == MYSQL_ERR_PACKET {
				break
			}

			// Parse row data
			rowData := parseRowData(pkt, int(columnCount))
			if len(rowData) > 0 {
				rowCount++
				result.WriteString(fmt.Sprintf("      %sRow %d:%s ", COLOR_YELLOW, rowCount, COLOR_DEFAULT))
				for i, val := range rowData {
					if i > 0 {
						result.WriteString(", ")
					}
					result.WriteString(fmt.Sprintf("%s%s%s=%s%s%s",
						COLOR_CYAN, columns[i], COLOR_DEFAULT,
						COLOR_WHITE, val, COLOR_DEFAULT))
				}
				result.WriteString("\n")
			}

			pktIdx++
		}

		if rowCount > 0 {
			result.WriteString(fmt.Sprintf("      %sTotal: %d row(s)%s", COLOR_GREEN, rowCount, COLOR_DEFAULT))
		} else {
			result.WriteString(fmt.Sprintf("      %s0 rows%s", COLOR_YELLOW, COLOR_DEFAULT))
		}
	}

	return result.String()
}

// parseColumnDefinition extracts column name from field packet
func parseColumnDefinition(data []byte) string {
	pos := 0

	// Skip catalog
	_, _, n, _ := mysql.LengthEncodedString(data[pos:])
	pos += n

	// Skip schema
	_, _, n, _ = mysql.LengthEncodedString(data[pos:])
	pos += n

	// Skip table
	_, _, n, _ = mysql.LengthEncodedString(data[pos:])
	pos += n

	// Skip org_table
	_, _, n, _ = mysql.LengthEncodedString(data[pos:])
	pos += n

	// Get column name
	name, _, _, _ := mysql.LengthEncodedString(data[pos:])

	return string(name)
}

// parseRowData extracts values from a row data packet
func parseRowData(data []byte, columnCount int) []string {
	var values []string
	pos := 0

	for i := 0; i < columnCount && pos < len(data); i++ {
		// Check for NULL value (0xfb)
		if data[pos] == 0xfb {
			values = append(values, "NULL")
			pos++
			continue
		}

		val, _, n, _ := mysql.LengthEncodedString(data[pos:])
		if n == 0 {
			break
		}

		values = append(values, string(val))
		pos += n
	}

	return values
}

// parseResponse parses a MySQL response packet
func parseResponse(data []byte, showRows bool) string {
	if len(data) < 1 {
		return "Empty response"
	}

	switch data[0] {
	case MYSQL_OK_PACKET:
		return parseOKPacket(data)
	case MYSQL_ERR_PACKET:
		return parseErrorPacket(data)
	case MYSQL_EOF_PACKET:
		return fmt.Sprintf("%sEOF%s", COLOR_YELLOW, COLOR_DEFAULT)
	default:
		// Could be a result set (first byte is column count)
		return parseResultSetPacket(data, showRows)
	}
}

// collectAllResponsePackets collects all packets from the response buffer
// This is needed for complete result set parsing
func collectAllResponsePackets(buffer []byte) [][]byte {
	var packets [][]byte
	buf := buffer

	for len(buf) >= 4 {
		// Get packet size (first 3 bytes, little-endian)
		size := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16
		if size == 0 || len(buf) < int(size)+4 {
			break
		}

		// Extract packet data (skip 4-byte header: 3 bytes size + 1 byte sequence)
		packetData := buf[4 : size+4]
		packets = append(packets, packetData)

		// Move to next packet
		buf = buf[size+4:]
	}

	return packets
}

// displayQueryResult displays a formatted query and its result
func displayQueryResult(src string, query string, responseData []byte, reqTime uint64, qbytes uint64, showRows bool) {
	if !verbose {
		return
	}

	var output bytes.Buffer

	// Display source
	output.WriteString(fmt.Sprintf("\n%s[%s]%s ", COLOR_CYAN, src, COLOR_DEFAULT))

	// Display query
	output.WriteString(fmt.Sprintf("%sCOM_QUERY%s (%s%.2fms%s, %s%d bytes%s)\n",
		COLOR_YELLOW, COLOR_DEFAULT,
		COLOR_GREEN, float64(reqTime)/1000000, COLOR_DEFAULT,
		COLOR_CYAN, qbytes, COLOR_DEFAULT))

	output.WriteString(fmt.Sprintf("  %sQuery:%s %s%s%s\n",
		COLOR_YELLOW, COLOR_DEFAULT,
		COLOR_WHITE, query, COLOR_DEFAULT))

	// Parse and display response
	if len(responseData) > 0 {
		// Check if this might be a complete result set by looking for multiple packets
		packets := collectAllResponsePackets(responseData)

		var result string
		if len(packets) > 1 && responseData[0] != MYSQL_OK_PACKET && responseData[0] != MYSQL_ERR_PACKET {
			// Multiple packets - likely a result set
			result = parseResultSetFull(packets, showRows)
		} else {
			// Single packet response
			result = parseResponse(responseData, showRows)
		}

		output.WriteString(fmt.Sprintf("  %sResult:%s %s\n", COLOR_YELLOW, COLOR_DEFAULT, result))
	}

	slog.Info(output.String())
}
