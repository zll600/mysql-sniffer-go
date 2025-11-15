package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	mysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	TOKEN_WORD       = 0
	TOKEN_QUOTE      = 1
	TOKEN_NUMBER     = 2
	TOKEN_WHITESPACE = 3
	TOKEN_OTHER      = 4

	// Internal tuning
	TIME_BUCKETS = 10000

	// ANSI colors
	COLOR_RED     = "\x1b[31m"
	COLOR_GREEN   = "\x1b[32m"
	COLOR_YELLOW  = "\x1b[33m"
	COLOR_CYAN    = "\x1b[36m"
	COLOR_WHITE   = "\x1b[37m"
	COLOR_DEFAULT = "\x1b[39m"

	// These are used for formatting outputs
	F_NONE = iota
	F_QUERY
	F_ROUTE
	F_SOURCE
	F_SOURCEIP
)

// CommandType represents a MySQL protocol command type
type CommandType byte

// String returns the human-readable name of the command type
func (c CommandType) String() string {
	switch byte(c) {
	case mysql.COM_SLEEP:
		return "COM_SLEEP"
	case mysql.COM_QUIT:
		return "COM_QUIT"
	case mysql.COM_INIT_DB:
		return "COM_INIT_DB"
	case mysql.COM_QUERY:
		return "COM_QUERY"
	case mysql.COM_FIELD_LIST:
		return "COM_FIELD_LIST"
	case mysql.COM_CREATE_DB:
		return "COM_CREATE_DB"
	case mysql.COM_DROP_DB:
		return "COM_DROP_DB"
	case mysql.COM_REFRESH:
		return "COM_REFRESH"
	case mysql.COM_SHUTDOWN:
		return "COM_SHUTDOWN"
	case mysql.COM_STATISTICS:
		return "COM_STATISTICS"
	case mysql.COM_PROCESS_INFO:
		return "COM_PROCESS_INFO"
	case mysql.COM_CONNECT:
		return "COM_CONNECT"
	case mysql.COM_PROCESS_KILL:
		return "COM_PROCESS_KILL"
	case mysql.COM_DEBUG:
		return "COM_DEBUG"
	case mysql.COM_PING:
		return "COM_PING"
	case mysql.COM_TIME:
		return "COM_TIME"
	case mysql.COM_DELAYED_INSERT:
		return "COM_DELAYED_INSERT"
	case mysql.COM_CHANGE_USER:
		return "COM_CHANGE_USER"
	case mysql.COM_BINLOG_DUMP:
		return "COM_BINLOG_DUMP"
	case mysql.COM_TABLE_DUMP:
		return "COM_TABLE_DUMP"
	case mysql.COM_CONNECT_OUT:
		return "COM_CONNECT_OUT"
	case mysql.COM_REGISTER_SLAVE:
		return "COM_REGISTER_SLAVE"
	case mysql.COM_STMT_PREPARE:
		return "COM_STMT_PREPARE"
	case mysql.COM_STMT_EXECUTE:
		return "COM_STMT_EXECUTE"
	case mysql.COM_STMT_SEND_LONG_DATA:
		return "COM_STMT_SEND_LONG_DATA"
	case mysql.COM_STMT_CLOSE:
		return "COM_STMT_CLOSE"
	case mysql.COM_STMT_RESET:
		return "COM_STMT_RESET"
	case mysql.COM_SET_OPTION:
		return "COM_SET_OPTION"
	case mysql.COM_STMT_FETCH:
		return "COM_STMT_FETCH"
	case mysql.COM_DAEMON:
		return "COM_DAEMON"
	case mysql.COM_BINLOG_DUMP_GTID:
		return "COM_BINLOG_DUMP_GTID"
	case mysql.COM_RESET_CONNECTION:
		return "COM_RESET_CONNECTION"
	default:
		return fmt.Sprintf("UNKNOWN_COMMAND_%d", c)
	}
}

// IsProcessable returns true if this command type can be processed by the sniffer
func (c CommandType) IsProcessable() bool {
	// Currently only COM_QUERY is processable
	return c == CommandType(mysql.COM_QUERY)
}

type packet struct {
	request bool // request or response
	data    []byte
}

type sortable struct {
	value float64
	line  string
}
type sortableSlice []sortable

type source struct {
	hostPort   string
	srcIP      string
	synced     bool
	reqBuffer  []byte
	respBuffer []byte
	reqSent    *time.Time
	reqTimes   [TIME_BUCKETS]uint64
	qBytes     uint64
	qData      *queryData
	qText      string
}

type queryData struct {
	count uint64
	bytes uint64
	times [TIME_BUCKETS]uint64
}

var start int64 = UnixNow()
var qbuf map[string]*queryData = make(map[string]*queryData)
var queryCount int
var chmap map[string]*source = make(map[string]*source)
var verbose bool = false
var noclean bool = false
var dirty bool = false
var showRows bool = false
var format []interface{}
var port uint16
var times [TIME_BUCKETS]uint64

var stats struct {
	packets struct {
		rcvd      uint64
		rcvd_sync uint64
	}
	desyncs uint64
	streams uint64
}

func UnixNow() int64 {
	return time.Now().Unix()
}

func main() {
	var lport = flag.Int("P", 3306, "MySQL port to use")
	var eth = flag.String("i", "eth0", "Interface to sniff")
	var ldirty = flag.Bool("u", false, "Unsanitized -- do not canonicalize queries")
	var period = flag.Int("t", 10, "Seconds between outputting status")
	var displaycount = flag.Int("d", 15, "Display this many queries in status updates")
	var doverbose = flag.Bool("v", false, "Print every query received (spammy)")
	var nocleanquery = flag.Bool("n", false, "no clean queries")
	var formatstr = flag.String("f", "#s:#q", "Format for output aggregation")
	var sortby = flag.String("s", "count", "Sort by: count, max, avg, maxbytes, avgbytes")
	var cutoff = flag.Int("c", 0, "Only show queries over count/second")
	var doshowrows = flag.Bool("r", false, "Show all result set rows (use with -v)")
	flag.Parse()

	verbose = *doverbose
	noclean = *nocleanquery
	showRows = *doshowrows
	port = uint16(*lport)
	dirty = *ldirty
	parseFormat(*formatstr)

	log.Printf("Initializing MySQL sniffing on %s:%d...", *eth, port)
	handle, err := pcap.OpenLive(*eth, 1024*1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device: %s", err.Error())
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("tcp port %d", port))
	if err != nil {
		log.Fatalf("Failed to set port filter: %s", err.Error())
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	last := time.Now().Unix()

	for packet := range packetSource.Packets() {
		handlePacket(packet)

		// simple output printer... this should be super fast since we expect that a
		// system like this will have relatively few unique queries once they're
		// canonicalized.
		if !verbose && queryCount%1000 == 0 && last < UnixNow()-int64(*period) {
			last = UnixNow()
			handleStatusUpdate(*displaycount, *sortby, *cutoff)
		}
	}
}

// extract the data using structured packet parsing with gopacket
func handlePacket(packet gopacket.Packet) {
	// Parse network layer to get IP addresses
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Parse transport layer to get TCP ports
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// Get IP layer for addresses
	var srcIP, dstIP string
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else {
		// TODO: Add IPv6 support
		return
	}

	// Extract ports
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	// Get application layer payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return
	}
	payload := applicationLayer.Payload()

	// If this is a 0-length payload, do nothing.
	if len(payload) <= 0 {
		return
	}

	// This is either an inbound or outbound packet. Determine by seeing which
	// end contains our port. Either way, we want to put this on the channel of
	// the remote end.
	var src string
	request := false
	if srcPort == port {
		src = fmt.Sprintf("%s:%d", dstIP, dstPort)
		slog.Info("response", "src", src)
	} else if dstPort == port {
		src = fmt.Sprintf("%s:%d", srcIP, srcPort)
		request = true
		slog.Info("request", "src", src)
	} else {
		slog.Error("got unexpected packet", "srcPort", srcPort, "dstPort", dstPort)
		os.Exit(1)
	}

	// Get the data structure for this source, then do something.
	rs, ok := chmap[src]
	if !ok {
		srcIP := src[0:strings.Index(src, ":")]
		rs = &source{hostPort: src, srcIP: srcIP, synced: false}
		stats.streams++
		chmap[src] = rs
	}

	// Now with a source, process the packet.
	processPacket(rs, request, payload)
}

// processPacket dispatches packet processing to request or response handler
func processPacket(rs *source, request bool, data []byte) {
	stats.packets.rcvd++
	if rs.synced {
		stats.packets.rcvd_sync++
	}

	if request {
		processRequest(rs, data)
	} else {
		processResponse(rs, data)
	}
}

// processRequest handles MySQL request packets (queries from client to server)
func processRequest(rs *source, data []byte) {
	slog.Info("receive request", "hostPort", rs.hostPort, "dataLength", len(data))

	// If we still have response buffer, we're in some weird state and
	// didn't successfully process the response.
	if rs.respBuffer != nil {
		stats.desyncs++
		rs.respBuffer = nil
		rs.synced = false
	}

	rs.reqBuffer = data
	pType, pData, err := carvePacket(&rs.reqBuffer)

	// Handle packet parsing errors (incomplete or malformed packets)
	if err != nil {
		slog.Debug("failed to parse packet", "error", err)
		return
	}

	// The synchronization logic: if we're not synced, we wait for a COM_QUERY
	if !rs.synced {
		if pType != CommandType(mysql.COM_QUERY) {
			rs.reqBuffer, rs.respBuffer = nil, nil
			return
		}
		rs.synced = true
	}

	// Parse COM_QUERY data to extract actual SQL query text
	// This handles both legacy format and MySQL 8.0.23+ query attributes
	var parsedQuery []byte
	if pType == CommandType(mysql.COM_QUERY) {
		var err error
		parsedQuery, err = parseComQuery(pData)
		if err != nil {
			slog.Debug("failed to parse COM_QUERY", "error", err)
			return
		}
	} else {
		// For non-COM_QUERY commands, use data as-is
		parsedQuery = pData
	}

	// Record request timestamp
	tnow := time.Now()
	// FIXME: why use pointer here
	rs.reqSent = &tnow

	// Increment query counter
	queryCount++

	// Format the query text according to user preferences
	text := formatQueryText(rs, parsedQuery)

	// Update query statistics
	plen := uint64(len(pData))
	qdata, ok := qbuf[text]
	if !ok {
		qdata = &queryData{}
		qbuf[text] = qdata
	}
	qdata.count++
	qdata.bytes += plen
	rs.qText, rs.qData, rs.qBytes = text, qdata, plen
}

// processResponse handles MySQL response packets (results from server to client)
func processResponse(rs *source, data []byte) {
	// Accumulate response data
	if rs.respBuffer == nil {
		rs.respBuffer = data
	} else {
		rs.respBuffer = append(rs.respBuffer, data...)
	}

	// If we haven't sent a request, we're still accumulating data
	if rs.reqSent == nil {
		if rs.qData != nil {
			rs.qData.bytes += uint64(len(data))
		}
		return
	}

	// Calculate request-response time
	reqtime := uint64(time.Since(*rs.reqSent).Nanoseconds())

	// Update timing statistics (per-source, global, and per-query)
	randn := rand.Intn(TIME_BUCKETS)
	rs.reqTimes[randn] = reqtime
	times[randn] = reqtime
	if rs.qData != nil {
		rs.qData.times[randn] = reqtime
		rs.qData.bytes += uint64(len(data))
	}

	// Clear request timestamp
	rs.reqSent = nil

	// Display parsed query and result in verbose mode
	if verbose && len(rs.qText) > 0 {
		displayQueryResult(rs.hostPort, rs.qText, rs.respBuffer, reqtime, rs.qBytes, showRows)
	}

	// Clear response buffer after processing
	rs.respBuffer = nil
}

// formatQueryText formats the query according to the user's format string
func formatQueryText(rs *source, pdata []byte) string {
	var text string

	for _, item := range format {
		switch item.(type) {
		case int:
			switch item.(int) {
			case F_NONE:
				log.Fatalf("F_NONE in format string")
			case F_QUERY:
				if dirty {
					text += string(pdata)
				} else {
					text += cleanupQuery(pdata)
				}
			case F_ROUTE:
				// Routes are in the query like:
				//     SELECT /* hostname:route */ FROM ...
				// We remove the hostname so routes can be condensed.
				parts := strings.SplitN(string(pdata), " ", 5)
				if len(parts) >= 4 && parts[1] == "/*" && parts[3] == "*/" {
					if strings.Contains(parts[2], ":") {
						text += strings.SplitN(parts[2], ":", 2)[1]
					} else {
						text += parts[2]
					}
				} else {
					text += "(unknown) " + cleanupQuery(pdata)
				}
			case F_SOURCE:
				text += rs.hostPort
			case F_SOURCEIP:
				text += rs.srcIP
			default:
				log.Fatalf("Unknown F_XXXXXX int in format string")
			}
		case string:
			text += item.(string)
		default:
			log.Fatalf("Unknown type in format string")
		}
	}

	return text
}

func calculateTimes(timings *[TIME_BUCKETS]uint64) (fmin, favg, fmax float64) {
	var counts, total, min, max, avg uint64 = 0, 0, 0, 0, 0
	has_min := false
	for _, val := range *timings {
		if val == 0 {
			// Queries should never take 0 nanoseconds. We are using 0 as a
			// trigger to mean 'uninitialized reading'.
			continue
		}
		if val < min || !has_min {
			has_min = true
			min = val
		}
		if val > max {
			max = val
		}
		counts++
		total += val
	}
	if counts > 0 {
		avg = total / counts // integer division
	}
	return float64(min) / 1000000, float64(avg) / 1000000,
		float64(max) / 1000000
}

func handleStatusUpdate(displaycount int, sortby string, cutoff int) {
	elapsed := float64(UnixNow() - start)

	// print status bar
	log.Printf("\n")
	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("%s%d total queries, %0.2f per second%s", COLOR_RED, queryCount,
		float64(queryCount)/elapsed, COLOR_DEFAULT)
	log.SetFlags(0)

	log.Printf("%d packets (%0.2f%% on synchronized streams) / %d desyncs / %d streams",
		stats.packets.rcvd, float64(stats.packets.rcvd_sync)/float64(stats.packets.rcvd)*100,
		stats.desyncs, stats.streams)

	// global timing values
	gmin, gavg, gmax := calculateTimes(&times)
	log.Printf("%0.2fms min / %0.2fms avg / %0.2fms max query times", gmin, gavg, gmax)
	log.Printf("%d unique results in this filter", len(qbuf))
	log.Printf(" ")
	log.Printf("%s count     %sqps     %s  min    avg   max      %sbytes      per qry%s",
		COLOR_YELLOW, COLOR_CYAN, COLOR_YELLOW, COLOR_GREEN, COLOR_DEFAULT)

	// we cheat so badly here...
	var tmp sortableSlice = make(sortableSlice, 0, len(qbuf))
	for q, c := range qbuf {
		qps := float64(c.count) / elapsed
		if qps < float64(cutoff) {
			continue
		}

		qmin, qavg, qmax := calculateTimes(&c.times)
		bavg := uint64(float64(c.bytes) / float64(c.count))

		sorted := float64(c.count)
		if sortby == "avg" {
			sorted = qavg
		} else if sortby == "max" {
			sorted = qmax
		} else if sortby == "maxbytes" {
			sorted = float64(c.bytes)
		} else if sortby == "avgbytes" {
			sorted = float64(bavg)
		}

		tmp = append(tmp, sortable{sorted, fmt.Sprintf(
			"%s%6d  %s%7.2f/s  %s%6.2f %6.2f %6.2f  %s%9db %6db %s%s%s",
			COLOR_YELLOW, c.count, COLOR_CYAN, qps, COLOR_YELLOW, qmin, qavg, qmax,
			COLOR_GREEN, c.bytes, bavg, COLOR_WHITE, q, COLOR_DEFAULT)})
	}
	sort.Sort(tmp)

	// now print top to bottom, since our sorted list is sorted backwards
	// from what we want
	if len(tmp) < displaycount {
		displaycount = len(tmp)
	}
	for i := 1; i <= displaycount; i++ {
		log.Printf("%s", tmp[len(tmp)-i].line)
	}
}

// carvePacket tries to pull a packet out of a slice of bytes. If so, it removes
// those bytes from the slice. Returns the command type, data payload, and any error.
func carvePacket(buf *[]byte) (CommandType, []byte, error) {
	dataLen := uint32(len(*buf))
	// MySQL packet minimum size: 4 bytes header + 1 byte command type
	if dataLen < 5 {
		return 0, nil, errors.New("buffer too small for MySQL packet header")
	}

	// Parse MySQL packet header
	// First three bytes: payload length (little-endian)
	// Fourth byte: sequence number
	// Fifth byte onwards: payload (command type + data)
	size := uint32((*buf)[0]) + uint32((*buf)[1])<<8 + uint32((*buf)[2])<<16

	// Validate packet completeness
	// size = payload length (includes command type byte)
	// total packet = 4 bytes header + size bytes payload
	if size == 0 || dataLen < size+4 {
		return 0, nil, errors.New("incomplete MySQL packet")
	}

	// Extract command type and data payload
	end := size + 4
	pType := CommandType((*buf)[4])
	data := (*buf)[5 : size+4]

	// Update buffer to remove processed packet
	if end >= dataLen {
		*buf = nil
	} else {
		*buf = (*buf)[end:]
	}

	slog.Info("carved Packet", "dataLen", dataLen, "size", size, "end", end, "pType", pType.String(), "dataLen", len(data), "bufRemaining", len(*buf))

	return pType, data, nil
}

// parseComQuery parses COM_QUERY packet data, handling both legacy format and
// MySQL 8.0.23+ format with query attributes
// Input: raw data after the COM_QUERY command byte (0x03)
// Returns: the actual SQL query text
func parseComQuery(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty COM_QUERY data")
	}

	// Detect format: MySQL 8.0.23+ query attributes start with length-encoded integers
	// SQL queries typically start with printable ASCII (S, s, I, i, U, u, D, d, etc.)
	// Length-encoded ints for small counts (0-250) will be bytes < 0xfb
	// If first byte is a common SQL keyword start letter, it's likely legacy format
	firstByte := data[0]

	// Heuristic: if first byte looks like it could be a length-encoded int (< 0x20 or in 0xfb-0xfe range),
	// try parsing as MySQL 8.0.23+ format
	// Common SQL starts: S(0x53), s(0x73), I(0x49), i(0x69), U(0x55), u(0x75), D(0x44), d(0x64), etc.
	if firstByte < 0x20 || firstByte >= 0xfb {
		// Likely MySQL 8.0.23+ format with query attributes
		offset := 0

		// Read parameter_count using go-mysql library function
		paramCount, isNull, bytesRead := mysql.LengthEncodedInt(data[offset:])
		if isNull || bytesRead == 0 {
			// If we can't parse as length-encoded int, treat as legacy format
			slog.Debug("failed to parse parameter_count, treating as legacy format", "isNull", isNull, "bytesRead", bytesRead)
			return data, nil
		}
		offset += bytesRead
		slog.Debug("parsed COM_QUERY", "parameter_count", paramCount, "bytesRead", bytesRead)

		// Read parameter_set_count
		if offset >= len(data) {
			return nil, errors.New("incomplete COM_QUERY: missing parameter_set_count")
		}
		paramSetCount, isNull, bytesRead := mysql.LengthEncodedInt(data[offset:])
		if isNull {
			return nil, errors.New("parameter_set_count is NULL")
		}
		offset += bytesRead
		slog.Debug("parsed COM_QUERY", "parameter_set_count", paramSetCount)

		// If there are parameters, we need to skip them
		// This is complex and involves parsing parameter types, names, and values
		// For now, we assume parameter_count = 0 (which is common for most queries)
		if paramCount > 0 {
			return nil, fmt.Errorf("COM_QUERY with parameters (parameter_count=%d) not yet supported", paramCount)
		}

		// The rest is the query text
		if offset >= len(data) {
			return nil, errors.New("incomplete COM_QUERY: missing query text")
		}
		return data[offset:], nil
	}

	// Legacy format: entire data is the query text
	return data, nil
}

// scans forward in the query given the current type and returns when we encounter
// a new type and need to stop scanning.  returns the size of the last token and
// the type of it.
func scanToken(query []byte) (length int, thistype int) {
	if len(query) < 1 {
		log.Fatalf("scanToken called with empty query")
	}

	//no clean queries
	if verbose && noclean {
		return len(query), TOKEN_OTHER
	}
	// peek at the first byte, then loop
	b := query[0]
	switch {
	case b == 39 || b == 34: // '"
		started_with := b
		escaped := false
		for i := 1; i < len(query); i++ {
			switch query[i] {
			case started_with:
				if escaped {
					escaped = false
					continue
				}
				return i + 1, TOKEN_QUOTE
			case 92:
				escaped = true
			default:
				escaped = false
			}
		}
		return len(query), TOKEN_QUOTE

	case b >= 48 && b <= 57: // 0-9
		for i := 1; i < len(query); i++ {
			switch {
			case query[i] >= 48 && query[i] <= 57: // 0-9
				// do nothing
			default:
				return i, TOKEN_NUMBER
			}
		}
		return len(query), TOKEN_NUMBER

	case b == 32 || (b >= 9 && b <= 13): // whitespace
		for i := 1; i < len(query); i++ {
			switch {
			case query[i] == 32 || (query[i] >= 9 && query[i] <= 13):
				// Eat all whitespace
			default:
				return i, TOKEN_WHITESPACE
			}
		}
		return len(query), TOKEN_WHITESPACE

	case (b >= 65 && b <= 90) || (b >= 97 && b <= 122): // a-zA-Z
		for i := 1; i < len(query); i++ {
			switch {
			case query[i] >= 48 && query[i] <= 57:
				// Numbers, allow.
			case (query[i] >= 65 && query[i] <= 90) || (query[i] >= 97 && query[i] <= 122):
				// Letters, allow.
			case query[i] == 36 || query[i] == 95:
				// $ and _
			default:
				return i, TOKEN_WORD
			}
		}
		return len(query), TOKEN_WORD

	default: // everything else
		return 1, TOKEN_OTHER
	}

	// shouldn't get here
	log.Fatalf("scanToken failure: [%s]", query)
	return
}

func cleanupQuery(query []byte) string {
	// iterate until we hit the end of the query...
	var qspace []string
	for i := 0; i < len(query); {
		length, toktype := scanToken(query[i:])

		switch toktype {
		case TOKEN_WORD, TOKEN_OTHER:
			qspace = append(qspace, string(query[i:i+length]))

		case TOKEN_NUMBER, TOKEN_QUOTE:
			qspace = append(qspace, "?")

		case TOKEN_WHITESPACE:
			qspace = append(qspace, " ")

		default:
			log.Fatalf("scanToken returned invalid token type %d", toktype)
		}

		i += length
	}

	// Remove hostname from the route information if it's present
	tmp := strings.Join(qspace, "")

	parts := strings.SplitN(tmp, " ", 5)
	if len(parts) >= 5 && parts[1] == "/*" && parts[3] == "*/" {
		if strings.Contains(parts[2], ":") {
			tmp = parts[0] + " /* " + strings.SplitN(parts[2], ":", 2)[1] + " */ " + parts[4]
		}
	}

	return strings.ReplaceAll(tmp, "?, ", "")
}

// parseFormat takes a string and parses it out into the given format slice
// that we later use to build up a string. This might actually be an overcomplicated
// solution?
func parseFormat(formatstr string) {
	formatstr = strings.TrimSpace(formatstr)
	if formatstr == "" {
		formatstr = "#b:#k"
	}

	is_special := false
	curstr := ""
	do_append := F_NONE
	for _, char := range formatstr {
		if char == '#' {
			if is_special {
				curstr += string(char)
				is_special = false
			} else {
				is_special = true
			}
			continue
		}

		if is_special {
			switch strings.ToLower(string(char)) {
			case "s":
				do_append = F_SOURCE
			case "i":
				do_append = F_SOURCEIP
			case "r":
				do_append = F_ROUTE
			case "q":
				do_append = F_QUERY
			default:
				curstr += "#" + string(char)
			}
			is_special = false
		} else {
			curstr += string(char)
		}

		if do_append != F_NONE {
			if curstr != "" {
				format = append(format, curstr, do_append)
				curstr = ""
			} else {
				format = append(format, do_append)
			}
			do_append = F_NONE
		}
	}
	if curstr != "" {
		format = append(format, curstr)
	}
}

func (s sortableSlice) Len() int {
	return len(s)
}

func (s sortableSlice) Less(i, j int) bool {
	return s[i].value < s[j].value
}

func (s sortableSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
