package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ── ANSI color codes ──────────────────────────────────────────────────────────
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorRed    = "\033[31m"
	colorBlue   = "\033[34m"
)

func green(s string) string  { return colorGreen + s + colorReset }
func yellow(s string) string { return colorYellow + s + colorReset }
func cyan(s string) string   { return colorCyan + s + colorReset }
func red(s string) string    { return colorRed + s + colorReset }
func bold(s string) string   { return colorBold + s + colorReset }
func dim(s string) string    { return colorDim + s + colorReset }
func blue(s string) string   { return colorBlue + s + colorReset }

// ── Config ────────────────────────────────────────────────────────────────────
type Config struct {
	TestDomain        string   `json:"test_domain"`
	TestPath          string   `json:"test_path"`
	Timeout           int      `json:"timeout"`
	MaxWorkers        int      `json:"max_workers"`
	TestDownload      bool     `json:"test_download"`
	DownloadSize      int      `json:"download_size"`
	Port              int      `json:"port"`
	Randomize         bool     `json:"randomize"`
	RandomIPsPerRange int      `json:"random_ips_per_range"`
	MixRanges         bool     `json:"mix_ranges"`
	OutputFile        string   `json:"output_file"`
	SortBy            string   `json:"sort_by"` // "latency", "speed", "ip"
	Subnets           []string `json:"subnets"`
}

// ── ScanResult ────────────────────────────────────────────────────────────────
type ScanResult struct {
	IP              string  `json:"ip"`
	LatencyMS       float64 `json:"latency_ms"`
	SpeedKBPS       float64 `json:"speed_kbps,omitempty"`
	DownloadedBytes int     `json:"downloaded_bytes,omitempty"`
	Status          string  `json:"status"`
	Timestamp       string  `json:"timestamp"`
}

// ── SortOption ────────────────────────────────────────────────────────────────
type SortOption int

const (
	SortByLatency SortOption = iota
	SortBySpeed
	SortByIP
	SortByDownloadedBytes
)

// ── Scanner ───────────────────────────────────────────────────────────────────
type Scanner struct {
	config       Config
	results      []ScanResult
	mu           sync.Mutex
	testedCount  atomic.Int64
	totalIPs     int64
	stopScan     atomic.Bool
	outputFile   *os.File
	outputFileMu sync.Mutex
	startTime    time.Time
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewScanner(config Config) *Scanner {
	if config.TestDomain == "" {
		config.TestDomain = "chatgpt.com"
	}
	if config.TestPath == "" {
		config.TestPath = "/"
	}
	if config.Timeout == 0 {
		config.Timeout = 3
	}
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 100
	}
	if config.DownloadSize == 0 {
		config.DownloadSize = 100 * 1024
	}
	if config.Port == 0 {
		config.Port = 443
	}
	if config.RandomIPsPerRange == 0 {
		config.RandomIPsPerRange = 10
	}
	if config.OutputFile == "" {
		config.OutputFile = "working_ips"
	}
	if config.SortBy == "" {
		config.SortBy = "latency"
	}

	// Clamp MaxWorkers to reasonable limits
	if config.MaxWorkers > 10000 {
		config.MaxWorkers = 10000
	}
	if config.MaxWorkers < 1 {
		config.MaxWorkers = 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Scanner{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *Scanner) clearOutputFile() error {
	f, err := os.Create(s.config.OutputFile + ".txt")
	if err != nil {
		return err
	}
	s.outputFile = f
	return nil
}

func (s *Scanner) saveIPRealtime(result ScanResult) {
	s.outputFileMu.Lock()
	defer s.outputFileMu.Unlock()
	if s.outputFile != nil {
		fmt.Fprintf(s.outputFile, "%s\n", result.IP)
	}
}

func (s *Scanner) Close() error {
	if s.outputFile != nil {
		return s.outputFile.Close()
	}
	return nil
}

// ── Sorting functions ─────────────────────────────────────────────────────��───
func (s *Scanner) sortResults(results []ScanResult, option SortOption) {
	switch option {
	case SortByLatency:
		sort.Slice(results, func(i, j int) bool {
			return results[i].LatencyMS < results[j].LatencyMS
		})
	case SortBySpeed:
		sort.Slice(results, func(i, j int) bool {
			return results[i].SpeedKBPS > results[j].SpeedKBPS
		})
	case SortByDownloadedBytes:
		sort.Slice(results, func(i, j int) bool {
			return results[i].DownloadedBytes > results[j].DownloadedBytes
		})
	case SortByIP:
		sort.Slice(results, func(i, j int) bool {
			return ipToUint32(results[i].IP) < ipToUint32(results[j].IP)
		})
	default:
		sort.Slice(results, func(i, j int) bool {
			return results[i].LatencyMS < results[j].LatencyMS
		})
	}
}

func (s *Scanner) getSortOption() SortOption {
	switch strings.ToLower(s.config.SortBy) {
	case "speed":
		return SortBySpeed
	case "ip":
		return SortByIP
	case "downloaded", "bytes":
		return SortByDownloadedBytes
	default:
		return SortByLatency
	}
}

// ── HTTP test ─────────────────────────────────────────────────────────────────
func (s *Scanner) testIPHTTP(ip string) *ScanResult {
	timeout := time.Duration(s.config.Timeout) * time.Second
	startTime := time.Now()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.config.TestDomain,
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 5 * time.Second,
	}

	rawConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", ip, s.config.Port))
	if err != nil {
		return nil
	}
	defer rawConn.Close()

	rawConn.SetDeadline(time.Now().Add(timeout))

	if tc, ok := rawConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		defer func() {
			if err != nil {
				tc.CloseRead()
				tc.CloseWrite()
			}
		}()
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return nil
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
		s.config.TestPath, s.config.TestDomain)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return nil
	}

	headerBuf := make([]byte, 20)
	headerFilled := 0
	buf := make([]byte, 32*1024)
	downloaded := 0

	for {
		n, err := tlsConn.Read(buf)
		if n > 0 {
			downloaded += n
			if headerFilled < 20 {
				need := 20 - headerFilled
				if need > n {
					need = n
				}
				copy(headerBuf[headerFilled:], buf[:need])
				headerFilled += need
			}
		}
		if err != nil {
			break
		}
		if s.config.TestDownload && downloaded >= s.config.DownloadSize {
			break
		}
	}

	elapsed := time.Since(startTime)

	if headerFilled < 5 || !strings.HasPrefix(string(headerBuf[:headerFilled]), "HTTP/") {
		return nil
	}

	latencyMS := float64(elapsed.Milliseconds())
	speedKBPS := 0.0
	if elapsed.Seconds() > 0 {
		speedKBPS = float64(downloaded) / 1024.0 / elapsed.Seconds()
	}

	return &ScanResult{
		IP:              ip,
		LatencyMS:       roundF(latencyMS, 2),
		SpeedKBPS:       roundF(speedKBPS, 2),
		DownloadedBytes: downloaded,
		Status:          "success",
		Timestamp:       time.Now().Format(time.RFC3339),
	}
}

// ── Fast TLS-only test ─────────────────────────────────────────────��──────────
func (s *Scanner) testIPFast(ip string) *ScanResult {
	timeout := time.Duration(s.config.Timeout) * time.Second
	startTime := time.Now()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.config.TestDomain,
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 5 * time.Second,
	}

	rawConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", ip, s.config.Port))
	if err != nil {
		return nil
	}
	defer rawConn.Close()

	rawConn.SetDeadline(time.Now().Add(timeout))

	if tc, ok := rawConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return nil
	}

	latencyMS := float64(time.Since(startTime).Milliseconds())

	return &ScanResult{
		IP:        ip,
		LatencyMS: roundF(latencyMS, 2),
		Status:    "success",
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

// ── scanIP ────────────────────────────────────────────────────────────────────
func (s *Scanner) scanIP(ip string) *ScanResult {
	if s.stopScan.Load() {
		return nil
	}

	var result *ScanResult
	if s.config.TestDownload {
		result = s.testIPHTTP(ip)
	} else {
		result = s.testIPFast(ip)
	}

	count := s.testedCount.Add(1)

	// Progress line every 500 IPs
	if count%500 == 0 {
		s.mu.Lock()
		found := len(s.results)
		s.mu.Unlock()
		elapsed := time.Since(s.startTime).Seconds()
		rate := 0.0
		if elapsed > 0 {
			rate = float64(count) / elapsed
		}
		pct := float64(count) / float64(s.totalIPs) * 100
		eta := ""
		if rate > 0 {
			remaining := float64(s.totalIPs-count) / rate
			eta = "  ETA " + fmtDuration(remaining)
		}
		fmt.Printf("  %s  %s/%s  %s  %s  %s%s\n",
			dim(fmt.Sprintf("[%5.1f%%]", pct)),
			cyan(fmt.Sprintf("%d", count)),
			dim(fmt.Sprintf("%d", s.totalIPs)),
			dim(fmt.Sprintf("%.0f ip/s", rate)),
			green(fmt.Sprintf("%d found", found)),
			dim("elapsed "+fmtDuration(elapsed)),
			dim(eta),
		)
	}

	if result != nil {
		s.mu.Lock()
		s.results = append(s.results, *result)
		found := len(s.results)
		s.mu.Unlock()

		s.saveIPRealtime(*result)

		speedStr := ""
		if result.SpeedKBPS > 0 {
			speedStr = "  " + yellow(fmt.Sprintf("%.0f KB/s", result.SpeedKBPS))
		}
		latStr := latencyColor(result.LatencyMS)(fmt.Sprintf("%6.0f ms", result.LatencyMS))
		fmt.Printf("  %s  #%-4d  %-17s  %s%s\n",
			green("✓"),
			found,
			bold(result.IP),
			latStr,
			speedStr,
		)
	}

	return result
}

// ── IP generation ─────────────────────────────────────────────────────────────
func ip4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func ipToUint32(ipStr string) uint32 {
	return ip4ToUint32(net.ParseIP(ipStr))
}

func uint32ToIP4(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", n>>24, (n>>16)&0xFF, (n>>8)&0xFF, n&0xFF)
}

type subnet24 struct{ base uint32 }

func parseTo24Ranges(subnets []string) []subnet24 {
	seen := make(map[uint32]bool)
	var ranges []subnet24

	for _, s := range subnets {
		_, network, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			logWarn("Cannot parse subnet " + s + ": " + err.Error())
			continue
		}
		ones, _ := network.Mask.Size()
		base := ip4ToUint32(network.IP.To4())

		if ones <= 24 {
			maskedBase := base &^ ((uint32(1) << (32 - uint(ones))) - 1)
			count := uint32(1) << (24 - uint(ones))
			for i := uint32(0); i < count; i++ {
				b24 := maskedBase + i<<8
				if !seen[b24] {
					seen[b24] = true
					ranges = append(ranges, subnet24{base: b24})
				}
			}
		} else {
			b24 := base & 0xFFFFFF00
			if !seen[b24] {
				seen[b24] = true
				ranges = append(ranges, subnet24{base: b24})
			}
		}
	}
	return ranges
}

func (s *Scanner) generateIPs(subnets []string) []string {
	logStep("Converting subnets to /24 ranges")
	ranges := parseTo24Ranges(subnets)
	logInfo("Unique /24 blocks : " + cyan(fmt.Sprintf("%d", len(ranges))))

	if s.config.MixRanges {
		logStep("Shuffling /24 ranges")
		rand.Shuffle(len(ranges), func(i, j int) { ranges[i], ranges[j] = ranges[j], ranges[i] })
	}

	var allIPs []string
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for _, r := range ranges {
		hosts := make([]uint32, 254)
		for i := range hosts {
			hosts[i] = r.base | uint32(i+1)
		}

		if s.config.Randomize {
			n := s.config.RandomIPsPerRange
			if n > 254 {
				n = 254
			}
			rng.Shuffle(254, func(i, j int) { hosts[i], hosts[j] = hosts[j], hosts[i] })
			hosts = hosts[:n]
		}

		for _, h := range hosts {
			allIPs = append(allIPs, uint32ToIP4(h))
		}
	}
	return allIPs
}

// ── ScanSubnets ───────────────────��───────────────────────────────────────────
func (s *Scanner) ScanSubnets(subnets []string) []ScanResult {
	printBanner()
	printConfig(s.config)

	logStep("Building IP list")
	ipList := s.generateIPs(subnets)
	s.totalIPs = int64(len(ipList))

	if s.totalIPs == 0 {
		logError("No IPs to scan — check your subnet list")
		return nil
	}

	if s.config.Randomize {
		logInfo(fmt.Sprintf("Randomize         : %s per /24",
			cyan(fmt.Sprintf("%d IPs", s.config.RandomIPsPerRange))))
	}
	if s.config.MixRanges {
		logInfo("Mix ranges        : " + green("enabled"))
	}
	logInfo("Total IPs to scan : " + bold(cyan(fmt.Sprintf("%d", s.totalIPs))))

	if err := s.clearOutputFile(); err != nil {
		logWarn(fmt.Sprintf("Could not open output file: %v", err))
	} else {
		logInfo("Live output       : " + yellow(s.config.OutputFile+".txt"))
	}

	printDivider()
	fmt.Println()

	s.startTime = time.Now()

	jobs := make(chan string, s.config.MaxWorkers)
	var wg sync.WaitGroup

	for i := 0; i < s.config.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if s.stopScan.Load() {
					continue
				}
				s.scanIP(ip)
			}
		}()
	}

	for _, ip := range ipList {
		if s.stopScan.Load() {
			break
		}
		jobs <- ip
	}
	close(jobs)
	wg.Wait()

	if err := s.Close(); err != nil {
		logWarn(fmt.Sprintf("Error closing output file: %v", err))
	}

	elapsed := time.Since(s.startTime)
	count := s.testedCount.Load()

	s.mu.Lock()
	found := len(s.results)
	sortOption := s.getSortOption()
	s.sortResults(s.results, sortOption)
	results := make([]ScanResult, len(s.results))
	copy(results, s.results)
	s.mu.Unlock()

	fmt.Println()
	printDivider()
	if s.stopScan.Load() {
		fmt.Printf("  %s  Scan interrupted\n", yellow("⚠"))
	} else {
		fmt.Printf("  %s  Scan complete\n", green("✓"))
	}
	printDivider()
	kv := func(k, v string) { fmt.Printf("  %-24s %s\n", dim(k), v) }
	kv("IPs scanned", bold(fmt.Sprintf("%d", count)))
	kv("Working IPs", bold(green(fmt.Sprintf("%d", found))))
	kv("Sorted by", bold(cyan(s.config.SortBy)))
	kv("Time elapsed", bold(fmtDuration(elapsed.Seconds())))
	if elapsed.Seconds() > 0 {
		kv("Scan rate", bold(fmt.Sprintf("%.0f IPs/s", float64(count)/elapsed.Seconds())))
	}
	if found > 0 {
		kv("Output file", yellow(s.config.OutputFile+".txt"))
	}
	printDivider()
	fmt.Println()

	return results
}

// ── SaveResults ───────────────────────────────────────────────────────────────
func (s *Scanner) SaveResults(results []ScanResult, filename string) error {
	type Output struct {
		ScanDate        string       `json:"scan_date"`
		TestDomain      string       `json:"test_domain"`
		TotalScanned    int64        `json:"total_scanned"`
		SortedBy        string       `json:"sorted_by"`
		WorkingIPsCount int          `json:"working_ips_count"`
		WorkingIPs      []ScanResult `json:"working_ips"`
	}
	out := Output{
		ScanDate:        time.Now().Format(time.RFC3339),
		TestDomain:      s.config.TestDomain,
		TotalScanned:    s.testedCount.Load(),
		SortedBy:        s.config.SortBy,
		WorkingIPsCount: len(results),
		WorkingIPs:      results,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return err
	}

	logInfo("JSON results saved to " + yellow(filename))
	return nil
}

// ── PrintTopIPs ───────────────────────────────────────────────────────────────
func (s *Scanner) PrintTopIPs(results []ScanResult, count int) {
	if len(results) == 0 {
		logWarn("No working IPs found")
		return
	}
	if count > len(results) {
		count = len(results)
	}

	fmt.Printf("\n  %s  Top %s working IPs (sorted by %s)\n\n",
		bold("★"), cyan(fmt.Sprintf("%d", count)), cyan(s.config.SortBy))

	switch strings.ToLower(s.config.SortBy) {
	case "speed":
		fmt.Printf("  %-4s  %-17s  %-12s  %-10s\n",
			dim("#"), dim("IP Address"), dim("Speed"), dim("Latency"))
		fmt.Printf("  %s\n", dim(strings.Repeat("─", 50)))

		for i, r := range results[:count] {
			speedStr := dim("—")
			if r.SpeedKBPS > 0 {
				speedStr = yellow(fmt.Sprintf("%.0f KB/s", r.SpeedKBPS))
			}
			latStr := latencyColor(r.LatencyMS)(fmt.Sprintf("%.0f ms", r.LatencyMS))
			fmt.Printf("  %-4s  %-17s  %-22s  %s\n",
				dim(fmt.Sprintf("%d", i+1)),
				bold(r.IP),
				speedStr,
				latStr,
			)
		}

	case "downloaded", "bytes":
		fmt.Printf("  %-4s  %-17s  %-12s  %-10s\n",
			dim("#"), dim("IP Address"), dim("Downloaded"), dim("Speed"))
		fmt.Printf("  %s\n", dim(strings.Repeat("─", 50)))

		for i, r := range results[:count] {
			downloadedStr := fmt.Sprintf("%d B", r.DownloadedBytes)
			if r.DownloadedBytes >= 1024*1024 {
				downloadedStr = fmt.Sprintf("%.1f MB", float64(r.DownloadedBytes)/(1024*1024))
			} else if r.DownloadedBytes >= 1024 {
				downloadedStr = fmt.Sprintf("%.1f KB", float64(r.DownloadedBytes)/1024)
			}
			speedStr := dim("—")
			if r.SpeedKBPS > 0 {
				speedStr = yellow(fmt.Sprintf("%.0f KB/s", r.SpeedKBPS))
			}
			fmt.Printf("  %-4s  %-17s  %-22s  %s\n",
				dim(fmt.Sprintf("%d", i+1)),
				bold(r.IP),
				yellow(downloadedStr),
				speedStr,
			)
		}

	case "ip":
		fmt.Printf("  %-4s  %-17s  %-10s  %-12s\n",
			dim("#"), dim("IP Address"), dim("Latency"), dim("Speed"))
		fmt.Printf("  %s\n", dim(strings.Repeat("─", 50)))

		for i, r := range results[:count] {
			latColored := latencyColor(r.LatencyMS)(fmt.Sprintf("%.0f ms", r.LatencyMS))
			speedStr := dim("—")
			if r.SpeedKBPS > 0 {
				speedStr = yellow(fmt.Sprintf("%.0f KB/s", r.SpeedKBPS))
			}
			fmt.Printf("  %-4s  %-17s  %-22s  %s\n",
				dim(fmt.Sprintf("%d", i+1)),
				bold(r.IP),
				latColored,
				speedStr,
			)
		}

	default: // latency (default)
		fmt.Printf("  %-4s  %-17s  %-10s  %-12s\n",
			dim("#"), dim("IP Address"), dim("Latency"), dim("Speed"))
		fmt.Printf("  %s\n", dim(strings.Repeat("─", 50)))

		for i, r := range results[:count] {
			latColored := latencyColor(r.LatencyMS)(fmt.Sprintf("%.0f ms", r.LatencyMS))
			speedStr := dim("—")
			if r.SpeedKBPS > 0 {
				speedStr = yellow(fmt.Sprintf("%.0f KB/s", r.SpeedKBPS))
			}
			fmt.Printf("  %-4s  %-17s  %-22s  %s\n",
				dim(fmt.Sprintf("%d", i+1)),
				bold(r.IP),
				latColored,
				speedStr,
			)
		}
	}
	fmt.Println()
}

// ── UI helpers ────────────────────────────────────────────────────────────────
func printBanner() {
	fmt.Println()
	fmt.Println("  " + bold(cyan("╔══════════════════════════════════════════╗")))
	fmt.Println("  " + bold(cyan("║")) + bold("    ☁  Cloudflare Edge IP Scanner         ") + bold(cyan("║")))
	fmt.Println("  " + bold(cyan("╚══════════════════════════════════════════╝")))
	fmt.Println()
}

func printConfig(c Config) {
	printDivider()
	kv := func(k, v string) { fmt.Printf("  %-22s %s\n", dim(k), v) }
	kv("Test domain", bold(c.TestDomain))
	kv("Port", fmt.Sprintf("%d", c.Port))
	kv("Timeout", fmt.Sprintf("%ds", c.Timeout))
	kv("Workers", cyan(fmt.Sprintf("%d", c.MaxWorkers)))
	kv("Sort by", cyan(c.SortBy))
	if c.TestDownload {
		kv("Mode", green("HTTP download")+" "+dim(fmt.Sprintf("(%.0f KB)", float64(c.DownloadSize)/1024)))
	} else {
		kv("Mode", yellow("TLS handshake only"))
	}
	printDivider()
	fmt.Println()
}

func printDivider() {
	fmt.Println("  " + dim(strings.Repeat("─", 50)))
}

func logStep(msg string)  { fmt.Printf("  %s  %s\n", blue("›"), bold(msg)) }
func logInfo(msg string)  { fmt.Printf("  %s  %s\n", dim("·"), msg) }
func logWarn(msg string)  { fmt.Printf("  %s  %s\n", yellow("!"), yellow(msg)) }
func logError(msg string) { fmt.Printf("  %s  %s\n", red("✗"), red(msg)) }

func latencyColor(ms float64) func(string) string {
	switch {
	case ms < 150:
		return green
	case ms < 400:
		return yellow
	default:
		return red
	}
}

func fmtDuration(secs float64) string {
	d := time.Duration(secs * float64(time.Second))
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

func roundF(v float64, decimals int) float64 {
	p := 1.0
	for i := 0; i < decimals; i++ {
		p *= 10
	}
	return float64(int(v*p+0.5)) / p
}

// ── File loader ───────────────────────────────────────────────────────────────
func loadSubnetsFromFile(filename string) []string {
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()

	var subnets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			subnets = append(subnets, line)
		}
	}
	if err := sc.Err(); err != nil {
		logWarn(fmt.Sprintf("Error reading subnets file: %v", err))
	}
	logInfo(fmt.Sprintf("Loaded %s subnets from %s",
		cyan(fmt.Sprintf("%d", len(subnets))), yellow(filename)))
	return subnets
}

func defaultConfig() Config {
	return Config{
		TestDomain:        "chatgpt.com",
		TestPath:          "/",
		Timeout:           3,
		MaxWorkers:        100,
		TestDownload:      true,
		DownloadSize:      102400,
		Port:              443,
		Randomize:         false,
		RandomIPsPerRange: 10,
		MixRanges:         false,
		OutputFile:        "working_ips",
		SortBy:            "latency",
		Subnets: []string{
			"8.6.112.0/24",
			"8.6.144.0/23",
			"8.6.146.0/24",
			"8.9.231.0/24",
			"8.10.148.0/24",
			"103.21.244.0/22",
			"103.22.200.0/22",
			"103.31.4.0/22",
			"104.16.0.0/13",
			"104.18.0.0/20",
			"104.24.0.0/14",
			"108.162.192.0/18",
			"141.101.64.0/18",
			"162.158.0.0/15",
			"173.245.48.0/20",
			"188.114.96.0/20",
			"190.93.240.0/20",
			"197.234.240.0/22",
			"198.41.128.0/17",
			"172.64.0.0/13",
			"131.0.72.0/22",
		},
	}
}

// ── main ──────────────────────────────────────────────────────────────────────
func main() {
	var config Config
	data, err := os.ReadFile("config.json")
	if err != nil {
		logWarn("config.json not found — creating default")
		config = defaultConfig()
		out, _ := json.MarshalIndent(config, "", "  ")
		if err := os.WriteFile("config.json", out, 0644); err != nil {
			logError(fmt.Sprintf("Cannot write config.json: %v", err))
			os.Exit(1)
		}
		logInfo("Edit config.json then run again")
		return
	}
	if err := json.Unmarshal(data, &config); err != nil {
		logError(fmt.Sprintf("Cannot parse config.json: %v", err))
		os.Exit(1)
	}

	subnets := loadSubnetsFromFile("subnets.txt")
	if len(subnets) == 0 {
		subnets = config.Subnets
	}
	if len(subnets) == 0 {
		logError("No subnets found — add subnets.txt or fill config.json")
		os.Exit(1)
	}

	scanner := NewScanner(config)
	defer scanner.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n  %s  Stopping gracefully...\n", yellow("⚠"))
		scanner.stopScan.Store(true)
		scanner.cancel()
	}()

	results := scanner.ScanSubnets(subnets)
	scanner.PrintTopIPs(results, 20)

	if err := scanner.SaveResults(results, "working_ips.json"); err != nil {
		logError(fmt.Sprintf("Cannot save results: %v", err))
		os.Exit(1)
	}
}
