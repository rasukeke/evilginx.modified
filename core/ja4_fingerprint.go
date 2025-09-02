package core

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"crypto/tls"
	"encoding/hex"
)

// JA4Fingerprint represents a JA4 fingerprint
type JA4Fingerprint struct {
	Raw        string
	Hash       string
	Version    string
	CipherSuites []uint16
	Extensions []uint16
	EllipticCurves []uint16
	SignatureAlgorithms []uint16
}

// BotDetectionResult represents the result of bot detection analysis
type BotDetectionResult struct {
	IsBot           bool
	Confidence      float64
	Reasons         []string
	JA4Fingerprint  *JA4Fingerprint
	HeaderAnomalies []string
	BlockAction     string // "allow", "block", "redirect", "rate_limit"
}

// JA4Detector handles JA4 fingerprinting and HTTP header analysis
type JA4Detector struct {
	knownBotFingerprints map[string]bool
	knownGoodFingerprints map[string]bool
	suspiciousUserAgents []string
	requiredHeaders      []string
	headerOrderPatterns  map[string]bool
}

// NewJA4Detector creates a new JA4 detector instance
func NewJA4Detector() *JA4Detector {
	detector := &JA4Detector{
		knownBotFingerprints:  make(map[string]bool),
		knownGoodFingerprints: make(map[string]bool),
		suspiciousUserAgents: []string{
			"python-requests",
			"curl",
			"wget",
			"Go-http-client",
			"libwww-perl",
			"PHP",
			"Java",
			"Apache-HttpClient",
			"okhttp",
			"Scrapy",
			"bot",
			"crawler",
			"spider",
			"scraper",
			"HeadlessChrome",
			"PhantomJS",
			"SlimerJS",
		},
		requiredHeaders: []string{
			"Accept",
			"Accept-Language",
			"Accept-Encoding",
			"User-Agent",
		},
		headerOrderPatterns: make(map[string]bool),
	}
	
	// Initialize known bot fingerprints (these would be populated from a database or config)
	detector.initializeBotFingerprints()
	
	return detector
}

// initializeBotFingerprints populates known bot fingerprints
func (jd *JA4Detector) initializeBotFingerprints() {
	// Common bot JA4 fingerprints (examples - in real implementation these would come from threat intelligence)
	botFingerprints := []string{
		"t13d1516h2_8daaf6152771_b0da82dd1658", // Example Python requests
		"t13d1715h2_5b57614c22b0_3d5424432c57", // Example curl
		"t13d1312h2_002f000500350084_0403050306", // Example Go http client
	}
	
	for _, fp := range botFingerprints {
		jd.knownBotFingerprints[fp] = true
	}
	
	// Known good fingerprints (legitimate browsers)
	goodFingerprints := []string{
		"t13d1516h2_8daaf6152771_b0da82dd1658", // Chrome
		"t13d1715h2_5b57614c22b0_3d5424432c57", // Firefox
		"t13d1312h2_002f000500350084_0403050306", // Safari
	}
	
	for _, fp := range goodFingerprints {
		jd.knownGoodFingerprints[fp] = true
	}
}

// GenerateJA4Fingerprint creates a JA4 fingerprint from TLS ClientHello
func (jd *JA4Detector) GenerateJA4Fingerprint(clientHello *tls.ClientHelloInfo) *JA4Fingerprint {
	if clientHello == nil {
		return nil
	}
	
	// JA4 format: [TLS Version][Cipher Suites Count][Extensions Count]h[Cipher Suites Hash]_[Extensions Hash]_[Signature Algorithms Hash]
	
	// TLS Version
	version := fmt.Sprintf("t%02x", clientHello.SupportedVersions[0])
	if len(clientHello.SupportedVersions) == 0 {
		version = "t00"
	}
	
	// Cipher Suites
	cipherSuites := clientHello.CipherSuites
	cipherCount := fmt.Sprintf("d%02d", len(cipherSuites))
	
	// Extensions (simulated - real implementation would parse from raw TLS data)
	extensions := []uint16{0, 5, 10, 11, 13, 16, 18, 21, 23, 35, 43, 45, 51}
	extCount := fmt.Sprintf("%02d", len(extensions))
	
	// Create hashes
	cipherHash := jd.hashUint16Slice(cipherSuites)
	extHash := jd.hashUint16Slice(extensions)
	
	// Signature algorithms (simulated)
	sigAlgs := []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806}
	sigHash := jd.hashUint16Slice(sigAlgs)
	
	// Construct JA4 fingerprint
	ja4Raw := fmt.Sprintf("%s%s%sh2_%s_%s_%s", version, cipherCount, extCount, cipherHash, extHash, sigHash)
	
	// Create hash of the full fingerprint
	hasher := sha256.New()
	hasher.Write([]byte(ja4Raw))
	ja4Hash := hex.EncodeToString(hasher.Sum(nil))[:12]
	
	return &JA4Fingerprint{
		Raw:                 ja4Raw,
		Hash:                ja4Hash,
		Version:             version,
		CipherSuites:        cipherSuites,
		Extensions:          extensions,
		SignatureAlgorithms: sigAlgs,
	}
}

// hashUint16Slice creates a hash from a slice of uint16 values
func (jd *JA4Detector) hashUint16Slice(values []uint16) string {
	if len(values) == 0 {
		return "000000000000"
	}
	
	// Sort values for consistent hashing
	sorted := make([]uint16, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	
	// Create string representation
	var parts []string
	for _, v := range sorted {
		parts = append(parts, fmt.Sprintf("%04x", v))
	}
	
	// Hash the concatenated string
	hasher := md5.New()
	hasher.Write([]byte(strings.Join(parts, "")))
	return hex.EncodeToString(hasher.Sum(nil))[:12]
}

// AnalyzeHeaders performs HTTP header analysis for bot detection
func (jd *JA4Detector) AnalyzeHeaders(headers map[string][]string) []string {
	var anomalies []string
	
	// Check User-Agent
	userAgent := getHeaderValue(headers, "User-Agent")
	if userAgent == "" {
		anomalies = append(anomalies, "missing_user_agent")
	} else {
		for _, suspicious := range jd.suspiciousUserAgents {
			if strings.Contains(strings.ToLower(userAgent), strings.ToLower(suspicious)) {
				anomalies = append(anomalies, fmt.Sprintf("suspicious_user_agent:%s", suspicious))
				break
			}
		}
	}
	
	// Check required headers
	for _, required := range jd.requiredHeaders {
		if getHeaderValue(headers, required) == "" {
			anomalies = append(anomalies, fmt.Sprintf("missing_header:%s", strings.ToLower(required)))
		}
	}
	
	// Check Accept header
	accept := getHeaderValue(headers, "Accept")
	if accept != "" {
		// Bots often have overly simple or missing Accept headers
		if accept == "*/*" || !strings.Contains(accept, "text/html") {
			anomalies = append(anomalies, "suspicious_accept_header")
		}
	}
	
	// Check Accept-Language
	acceptLang := getHeaderValue(headers, "Accept-Language")
	if acceptLang == "" {
		anomalies = append(anomalies, "missing_accept_language")
	}
	
	// Check Accept-Encoding
	acceptEnc := getHeaderValue(headers, "Accept-Encoding")
	if acceptEnc == "" {
		anomalies = append(anomalies, "missing_accept_encoding")
	}
	
	// Check for common bot headers
	botHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Originating-IP",
		"X-Remote-IP",
		"X-Remote-Addr",
	}
	
	for _, botHeader := range botHeaders {
		if getHeaderValue(headers, botHeader) != "" {
			anomalies = append(anomalies, fmt.Sprintf("bot_header_present:%s", strings.ToLower(botHeader)))
		}
	}
	
	// Check header order (simplified - real implementation would be more sophisticated)
	headerOrder := jd.getHeaderOrder(headers)
	if jd.isAnomalousHeaderOrder(headerOrder) {
		anomalies = append(anomalies, "anomalous_header_order")
	}
	
	return anomalies
}

// getHeaderValue safely gets a header value
func getHeaderValue(headers map[string][]string, key string) string {
	if values, exists := headers[key]; exists && len(values) > 0 {
		return values[0]
	}
	return ""
}

// getHeaderOrder returns the order of headers
func (jd *JA4Detector) getHeaderOrder(headers map[string][]string) []string {
	var order []string
	for key := range headers {
		order = append(order, strings.ToLower(key))
	}
	return order
}

// isAnomalousHeaderOrder checks if header order is suspicious
func (jd *JA4Detector) isAnomalousHeaderOrder(order []string) bool {
	// Simple check - real implementation would use machine learning or statistical analysis
	orderStr := strings.Join(order, ",")
	
	// Check against known bad patterns
	suspiciousPatterns := []string{
		"user-agent,accept,accept-encoding", // Too simple
		"host,user-agent",                   // Missing common headers
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(orderStr, pattern) {
			return true
		}
	}
	
	return false
}

// DetectBot performs comprehensive bot detection
func (jd *JA4Detector) DetectBot(ja4 *JA4Fingerprint, headers map[string][]string) *BotDetectionResult {
	result := &BotDetectionResult{
		IsBot:           false,
		Confidence:      0.0,
		Reasons:         []string{},
		JA4Fingerprint:  ja4,
		HeaderAnomalies: []string{},
		BlockAction:     "allow",
	}
	
	confidence := 0.0
	
	// JA4 fingerprint analysis
	if ja4 != nil {
		if jd.knownBotFingerprints[ja4.Hash] {
			confidence += 0.8
			result.Reasons = append(result.Reasons, "known_bot_ja4_fingerprint")
		} else if jd.knownGoodFingerprints[ja4.Hash] {
			confidence -= 0.3 // Reduce suspicion for known good fingerprints
		}
	}
	
	// HTTP header analysis
	headerAnomalies := jd.AnalyzeHeaders(headers)
	result.HeaderAnomalies = headerAnomalies
	
	// Calculate confidence based on anomalies
	for _, anomaly := range headerAnomalies {
		switch {
		case strings.Contains(anomaly, "suspicious_user_agent"):
			confidence += 0.7
			result.Reasons = append(result.Reasons, anomaly)
		case strings.Contains(anomaly, "missing_user_agent"):
			confidence += 0.9
			result.Reasons = append(result.Reasons, anomaly)
		case strings.Contains(anomaly, "missing_header"):
			confidence += 0.3
			result.Reasons = append(result.Reasons, anomaly)
		case strings.Contains(anomaly, "bot_header_present"):
			confidence += 0.5
			result.Reasons = append(result.Reasons, anomaly)
		case strings.Contains(anomaly, "anomalous_header_order"):
			confidence += 0.4
			result.Reasons = append(result.Reasons, anomaly)
		default:
			confidence += 0.2
			result.Reasons = append(result.Reasons, anomaly)
		}
	}
	
	// Normalize confidence to 0-1 range
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}
	
	result.Confidence = confidence
	
	// Determine if it's a bot and what action to take
	if confidence >= 0.8 {
		result.IsBot = true
		result.BlockAction = "block"
	} else if confidence >= 0.6 {
		result.IsBot = true
		result.BlockAction = "rate_limit"
	} else if confidence >= 0.4 {
		result.IsBot = false // Suspicious but not definitive
		result.BlockAction = "monitor"
	} else {
		result.IsBot = false
		result.BlockAction = "allow"
	}
	
	return result
}

// AddBotFingerprint adds a fingerprint to the bot blacklist
func (jd *JA4Detector) AddBotFingerprint(fingerprint string) {
	jd.knownBotFingerprints[fingerprint] = true
}

// AddGoodFingerprint adds a fingerprint to the good whitelist
func (jd *JA4Detector) AddGoodFingerprint(fingerprint string) {
	jd.knownGoodFingerprints[fingerprint] = true
}

// UpdateSuspiciousUserAgents updates the list of suspicious user agents
func (jd *JA4Detector) UpdateSuspiciousUserAgents(userAgents []string) {
	jd.suspiciousUserAgents = userAgents
}

