package core

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// BehavioralData represents data collected from JavaScript behavioral checks
type BehavioralData struct {
	SessionID           string                 `json:"session_id"`
	Timestamp           int64                  `json:"timestamp"`
	UserAgent           string                 `json:"user_agent"`
	ScreenResolution    string                 `json:"screen_resolution"`
	ViewportSize        string                 `json:"viewport_size"`
	TimezoneOffset      int                    `json:"timezone_offset"`
	Language            string                 `json:"language"`
	Platform            string                 `json:"platform"`
	CookieEnabled       bool                   `json:"cookie_enabled"`
	DoNotTrack          string                 `json:"do_not_track"`
	MouseMovements      []MouseEvent           `json:"mouse_movements"`
	KeyboardEvents      []KeyboardEvent        `json:"keyboard_events"`
	TouchEvents         []TouchEvent           `json:"touch_events"`
	CanvasFingerprint   string                 `json:"canvas_fingerprint"`
	WebGLFingerprint    string                 `json:"webgl_fingerprint"`
	AudioFingerprint    string                 `json:"audio_fingerprint"`
	FontList            []string               `json:"font_list"`
	PluginList          []string               `json:"plugin_list"`
	HeadlessIndicators  map[string]interface{} `json:"headless_indicators"`
	PerformanceMetrics  PerformanceData        `json:"performance_metrics"`
	BehaviorScore       float64                `json:"behavior_score"`
}

// MouseEvent represents a mouse movement or click event
type MouseEvent struct {
	Type      string  `json:"type"`      // "move", "click", "scroll"
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Timestamp int64   `json:"timestamp"`
	Button    int     `json:"button,omitempty"`
}

// KeyboardEvent represents a keyboard event
type KeyboardEvent struct {
	Type      string `json:"type"`      // "keydown", "keyup", "keypress"
	Key       string `json:"key"`
	Code      string `json:"code"`
	Timestamp int64  `json:"timestamp"`
	CtrlKey   bool   `json:"ctrl_key"`
	AltKey    bool   `json:"alt_key"`
	ShiftKey  bool   `json:"shift_key"`
}

// TouchEvent represents a touch event
type TouchEvent struct {
	Type      string  `json:"type"`      // "touchstart", "touchmove", "touchend"
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Timestamp int64   `json:"timestamp"`
	Force     float64 `json:"force,omitempty"`
}

// PerformanceData represents performance metrics
type PerformanceData struct {
	LoadTime        int64 `json:"load_time"`
	DOMContentTime  int64 `json:"dom_content_time"`
	FirstPaintTime  int64 `json:"first_paint_time"`
	JSExecutionTime int64 `json:"js_execution_time"`
}

// BehavioralAnalyzer analyzes behavioral data for bot detection
type BehavioralAnalyzer struct {
	config *BehavioralConfig
}

// BehavioralConfig contains configuration for behavioral analysis
type BehavioralConfig struct {
	MinMouseMovements     int     `json:"min_mouse_movements"`
	MaxMouseSpeed         float64 `json:"max_mouse_speed"`
	MinMouseEntropy       float64 `json:"min_mouse_entropy"`
	MaxTypingSpeed        float64 `json:"max_typing_speed"`
	MinPageLoadTime       int64   `json:"min_page_load_time"`
	MaxPageLoadTime       int64   `json:"max_page_load_time"`
	RequiredJSFeatures    []string `json:"required_js_features"`
	SuspiciousIndicators  []string `json:"suspicious_indicators"`
	BotThreshold          float64 `json:"bot_threshold"`
}

// NewBehavioralAnalyzer creates a new behavioral analyzer
func NewBehavioralAnalyzer() *BehavioralAnalyzer {
	config := &BehavioralConfig{
		MinMouseMovements:    5,
		MaxMouseSpeed:        2000.0, // pixels per second
		MinMouseEntropy:      0.3,
		MaxTypingSpeed:       15.0, // characters per second
		MinPageLoadTime:      100,  // milliseconds
		MaxPageLoadTime:      30000, // milliseconds
		RequiredJSFeatures:   []string{"canvas", "webgl", "audio"},
		SuspiciousIndicators: []string{"webdriver", "phantom", "selenium", "chrome.runtime"},
		BotThreshold:         0.6,
	}
	
	return &BehavioralAnalyzer{
		config: config,
	}
}

// GenerateBehavioralJS generates JavaScript code for behavioral detection
func (ba *BehavioralAnalyzer) GenerateBehavioralJS(sessionID string) string {
	js := fmt.Sprintf(`
<script>
(function() {
    'use strict';
    
    var behaviorData = {
        session_id: '%s',
        timestamp: Date.now(),
        user_agent: navigator.userAgent,
        screen_resolution: screen.width + 'x' + screen.height,
        viewport_size: window.innerWidth + 'x' + window.innerHeight,
        timezone_offset: new Date().getTimezoneOffset(),
        language: navigator.language,
        platform: navigator.platform,
        cookie_enabled: navigator.cookieEnabled,
        do_not_track: navigator.doNotTrack || 'unspecified',
        mouse_movements: [],
        keyboard_events: [],
        touch_events: [],
        canvas_fingerprint: '',
        webgl_fingerprint: '',
        audio_fingerprint: '',
        font_list: [],
        plugin_list: [],
        headless_indicators: {},
        performance_metrics: {},
        behavior_score: 0
    };
    
    var startTime = Date.now();
    var mouseMovementCount = 0;
    var keyboardEventCount = 0;
    var lastMouseEvent = 0;
    var lastKeyboardEvent = 0;
    
    // Mouse movement tracking
    function trackMouseMovement(e) {
        var now = Date.now();
        if (now - lastMouseEvent > 50) { // Throttle to avoid too much data
            behaviorData.mouse_movements.push({
                type: 'move',
                x: e.clientX,
                y: e.clientY,
                timestamp: now
            });
            mouseMovementCount++;
            lastMouseEvent = now;
        }
    }
    
    // Mouse click tracking
    function trackMouseClick(e) {
        behaviorData.mouse_movements.push({
            type: 'click',
            x: e.clientX,
            y: e.clientY,
            timestamp: Date.now(),
            button: e.button
        });
    }
    
    // Keyboard event tracking
    function trackKeyboard(e) {
        var now = Date.now();
        if (now - lastKeyboardEvent > 50) { // Throttle
            behaviorData.keyboard_events.push({
                type: e.type,
                key: e.key,
                code: e.code,
                timestamp: now,
                ctrl_key: e.ctrlKey,
                alt_key: e.altKey,
                shift_key: e.shiftKey
            });
            keyboardEventCount++;
            lastKeyboardEvent = now;
        }
    }
    
    // Touch event tracking
    function trackTouch(e) {
        if (e.touches && e.touches.length > 0) {
            var touch = e.touches[0];
            behaviorData.touch_events.push({
                type: e.type,
                x: touch.clientX,
                y: touch.clientY,
                timestamp: Date.now(),
                force: touch.force || 0
            });
        }
    }
    
    // Canvas fingerprinting
    function generateCanvasFingerprint() {
        try {
            var canvas = document.createElement('canvas');
            var ctx = canvas.getContext('2d');
            canvas.width = 200;
            canvas.height = 50;
            
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('BotDetect 🤖', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('BotDetect 🤖', 4, 17);
            
            return canvas.toDataURL();
        } catch (e) {
            return 'error';
        }
    }
    
    // WebGL fingerprinting
    function generateWebGLFingerprint() {
        try {
            var canvas = document.createElement('canvas');
            var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return 'not_supported';
            
            var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            var vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            
            return vendor + '|' + renderer;
        } catch (e) {
            return 'error';
        }
    }
    
    // Audio fingerprinting
    function generateAudioFingerprint() {
        try {
            var audioContext = new (window.AudioContext || window.webkitAudioContext)();
            var oscillator = audioContext.createOscillator();
            var analyser = audioContext.createAnalyser();
            var gainNode = audioContext.createGain();
            var scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
            
            oscillator.type = 'triangle';
            oscillator.frequency.value = 10000;
            
            gainNode.gain.value = 0;
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.start(0);
            
            var audioData = new Float32Array(analyser.frequencyBinCount);
            analyser.getFloatFrequencyData(audioData);
            
            oscillator.stop();
            audioContext.close();
            
            return audioData.slice(0, 10).join(',');
        } catch (e) {
            return 'error';
        }
    }
    
    // Font detection
    function detectFonts() {
        var fonts = ['Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS', 'Trebuchet MS', 'Arial Black', 'Impact'];
        var detectedFonts = [];
        
        var testString = 'mmmmmmmmmmlli';
        var testSize = '72px';
        var h = document.getElementsByTagName('body')[0];
        
        var s = document.createElement('span');
        s.style.fontSize = testSize;
        s.innerHTML = testString;
        var defaultWidth = {};
        var defaultHeight = {};
        
        for (var index in fonts) {
            s.style.fontFamily = fonts[index];
            h.appendChild(s);
            defaultWidth[fonts[index]] = s.offsetWidth;
            defaultHeight[fonts[index]] = s.offsetHeight;
            h.removeChild(s);
        }
        
        return fonts.filter(function(font) {
            return defaultWidth[font] !== defaultWidth['Arial'] || defaultHeight[font] !== defaultHeight['Arial'];
        });
    }
    
    // Plugin detection
    function detectPlugins() {
        var plugins = [];
        for (var i = 0; i < navigator.plugins.length; i++) {
            plugins.push(navigator.plugins[i].name);
        }
        return plugins;
    }
    
    // Headless browser detection
    function detectHeadlessIndicators() {
        var indicators = {};
        
        // Check for webdriver
        indicators.webdriver = navigator.webdriver || false;
        
        // Check for phantom
        indicators.phantom = window.callPhantom || window._phantom || false;
        
        // Check for selenium
        indicators.selenium = window.document.$cdc_asdjflasutopfhvcZLmcfl_ || window.document.documentElement.getAttribute('selenium') || window.document.documentElement.getAttribute('webdriver') || window.document.documentElement.getAttribute('driver') || false;
        
        // Check for chrome runtime
        indicators.chrome_runtime = window.chrome && window.chrome.runtime && window.chrome.runtime.onConnect || false;
        
        // Check for missing image
        indicators.missing_image = !window.Image || false;
        
        // Check for permissions
        indicators.permissions = navigator.permissions && navigator.permissions.query || false;
        
        // Check for notification
        indicators.notification = window.Notification && Notification.permission || false;
        
        // Check for external
        indicators.external = window.external && window.external.AddSearchProvider || false;
        
        return indicators;
    }
    
    // Performance metrics
    function getPerformanceMetrics() {
        var perf = window.performance;
        if (!perf || !perf.timing) return {};
        
        var timing = perf.timing;
        return {
            load_time: timing.loadEventEnd - timing.navigationStart,
            dom_content_time: timing.domContentLoadedEventEnd - timing.navigationStart,
            first_paint_time: perf.getEntriesByType && perf.getEntriesByType('paint').length > 0 ? perf.getEntriesByType('paint')[0].startTime : 0,
            js_execution_time: Date.now() - startTime
        };
    }
    
    // Calculate behavior score
    function calculateBehaviorScore() {
        var score = 0;
        var factors = 0;
        
        // Mouse movement analysis
        if (behaviorData.mouse_movements.length > 0) {
            var mouseEntropy = calculateMouseEntropy(behaviorData.mouse_movements);
            var mouseSpeed = calculateAverageMouseSpeed(behaviorData.mouse_movements);
            
            if (mouseEntropy > 0.3) score += 0.2;
            if (mouseSpeed < 2000 && mouseSpeed > 10) score += 0.2;
            factors += 2;
        } else {
            score -= 0.3; // No mouse movement is suspicious
        }
        
        // Keyboard analysis
        if (behaviorData.keyboard_events.length > 0) {
            var typingSpeed = calculateTypingSpeed(behaviorData.keyboard_events);
            if (typingSpeed < 15 && typingSpeed > 0.5) score += 0.2;
            factors += 1;
        }
        
        // Headless indicators
        var headlessCount = 0;
        for (var key in behaviorData.headless_indicators) {
            if (behaviorData.headless_indicators[key]) headlessCount++;
        }
        if (headlessCount === 0) score += 0.3;
        else score -= headlessCount * 0.2;
        factors += 1;
        
        // Canvas and WebGL support
        if (behaviorData.canvas_fingerprint && behaviorData.canvas_fingerprint !== 'error') score += 0.1;
        if (behaviorData.webgl_fingerprint && behaviorData.webgl_fingerprint !== 'error' && behaviorData.webgl_fingerprint !== 'not_supported') score += 0.1;
        factors += 2;
        
        // Font detection
        if (behaviorData.font_list.length > 5) score += 0.1;
        factors += 1;
        
        return Math.max(0, Math.min(1, score / factors));
    }
    
    // Helper functions
    function calculateMouseEntropy(movements) {
        if (movements.length < 2) return 0;
        
        var distances = [];
        for (var i = 1; i < movements.length; i++) {
            var dx = movements[i].x - movements[i-1].x;
            var dy = movements[i].y - movements[i-1].y;
            distances.push(Math.sqrt(dx*dx + dy*dy));
        }
        
        var mean = distances.reduce(function(a, b) { return a + b; }, 0) / distances.length;
        var variance = distances.reduce(function(a, b) { return a + Math.pow(b - mean, 2); }, 0) / distances.length;
        
        return variance / (mean * mean + 1); // Normalized entropy
    }
    
    function calculateAverageMouseSpeed(movements) {
        if (movements.length < 2) return 0;
        
        var totalDistance = 0;
        var totalTime = 0;
        
        for (var i = 1; i < movements.length; i++) {
            var dx = movements[i].x - movements[i-1].x;
            var dy = movements[i].y - movements[i-1].y;
            var distance = Math.sqrt(dx*dx + dy*dy);
            var time = movements[i].timestamp - movements[i-1].timestamp;
            
            totalDistance += distance;
            totalTime += time;
        }
        
        return totalTime > 0 ? (totalDistance / totalTime) * 1000 : 0; // pixels per second
    }
    
    function calculateTypingSpeed(events) {
        if (events.length < 2) return 0;
        
        var keyPresses = events.filter(function(e) { return e.type === 'keydown' && e.key.length === 1; });
        if (keyPresses.length < 2) return 0;
        
        var totalTime = keyPresses[keyPresses.length - 1].timestamp - keyPresses[0].timestamp;
        return totalTime > 0 ? (keyPresses.length / totalTime) * 1000 : 0; // characters per second
    }
    
    // Event listeners
    document.addEventListener('mousemove', trackMouseMovement, true);
    document.addEventListener('click', trackMouseClick, true);
    document.addEventListener('keydown', trackKeyboard, true);
    document.addEventListener('keyup', trackKeyboard, true);
    document.addEventListener('touchstart', trackTouch, true);
    document.addEventListener('touchmove', trackTouch, true);
    document.addEventListener('touchend', trackTouch, true);
    
    // Initialize fingerprints
    behaviorData.canvas_fingerprint = generateCanvasFingerprint();
    behaviorData.webgl_fingerprint = generateWebGLFingerprint();
    behaviorData.audio_fingerprint = generateAudioFingerprint();
    behaviorData.font_list = detectFonts();
    behaviorData.plugin_list = detectPlugins();
    behaviorData.headless_indicators = detectHeadlessIndicators();
    
    // Send data after a delay to collect behavioral data
    setTimeout(function() {
        behaviorData.performance_metrics = getPerformanceMetrics();
        behaviorData.behavior_score = calculateBehaviorScore();
        
        // Send data to server
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/behavioral-data', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(behaviorData));
    }, 3000); // Wait 3 seconds to collect behavioral data
    
    // Send data on page unload as well
    window.addEventListener('beforeunload', function() {
        behaviorData.performance_metrics = getPerformanceMetrics();
        behaviorData.behavior_score = calculateBehaviorScore();
        
        if (navigator.sendBeacon) {
            navigator.sendBeacon('/behavioral-data', JSON.stringify(behaviorData));
        }
    });
})();
</script>`, sessionID)
	
	return js
}

// AnalyzeBehavioralData analyzes the collected behavioral data
func (ba *BehavioralAnalyzer) AnalyzeBehavioralData(data *BehavioralData) *BotDetectionResult {
	result := &BotDetectionResult{
		IsBot:       false,
		Confidence:  0.0,
		Reasons:     []string{},
		BlockAction: "allow",
	}
	
	confidence := 0.0
	
	// Analyze mouse movements
	if len(data.MouseMovements) < ba.config.MinMouseMovements {
		confidence += 0.4
		result.Reasons = append(result.Reasons, "insufficient_mouse_movements")
	} else {
		// Check mouse movement patterns
		entropy := ba.calculateMouseEntropy(data.MouseMovements)
		if entropy < ba.config.MinMouseEntropy {
			confidence += 0.3
			result.Reasons = append(result.Reasons, "low_mouse_entropy")
		}
		
		avgSpeed := ba.calculateAverageMouseSpeed(data.MouseMovements)
		if avgSpeed > ba.config.MaxMouseSpeed {
			confidence += 0.5
			result.Reasons = append(result.Reasons, "excessive_mouse_speed")
		}
	}
	
	// Analyze keyboard events
	if len(data.KeyboardEvents) > 0 {
		typingSpeed := ba.calculateTypingSpeed(data.KeyboardEvents)
		if typingSpeed > ba.config.MaxTypingSpeed {
			confidence += 0.4
			result.Reasons = append(result.Reasons, "excessive_typing_speed")
		}
	}
	
	// Check headless indicators
	headlessCount := 0
	for key, value := range data.HeadlessIndicators {
		if value == true {
			headlessCount++
			confidence += 0.6
			result.Reasons = append(result.Reasons, fmt.Sprintf("headless_indicator:%s", key))
		}
	}
	
	// Check performance metrics
	if data.PerformanceMetrics.LoadTime < ba.config.MinPageLoadTime {
		confidence += 0.3
		result.Reasons = append(result.Reasons, "suspiciously_fast_load_time")
	}
	
	if data.PerformanceMetrics.LoadTime > ba.config.MaxPageLoadTime {
		confidence += 0.2
		result.Reasons = append(result.Reasons, "suspiciously_slow_load_time")
	}
	
	// Check fingerprints
	if data.CanvasFingerprint == "error" || data.CanvasFingerprint == "" {
		confidence += 0.3
		result.Reasons = append(result.Reasons, "missing_canvas_support")
	}
	
	if data.WebGLFingerprint == "error" || data.WebGLFingerprint == "not_supported" {
		confidence += 0.2
		result.Reasons = append(result.Reasons, "missing_webgl_support")
	}
	
	// Check font list
	if len(data.FontList) < 3 {
		confidence += 0.2
		result.Reasons = append(result.Reasons, "limited_font_support")
	}
	
	// Use the client-side calculated behavior score
	if data.BehaviorScore < 0.3 {
		confidence += 0.4
		result.Reasons = append(result.Reasons, "low_behavior_score")
	}
	
	// Normalize confidence
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	result.Confidence = confidence
	
	// Determine action based on confidence
	if confidence >= ba.config.BotThreshold {
		result.IsBot = true
		if confidence >= 0.8 {
			result.BlockAction = "block"
		} else {
			result.BlockAction = "rate_limit"
		}
	} else if confidence >= 0.4 {
		result.IsBot = false
		result.BlockAction = "monitor"
	} else {
		result.IsBot = false
		result.BlockAction = "allow"
	}
	
	return result
}

// Helper methods for behavioral analysis
func (ba *BehavioralAnalyzer) calculateMouseEntropy(movements []MouseEvent) float64 {
	if len(movements) < 2 {
		return 0.0
	}
	
	var distances []float64
	for i := 1; i < len(movements); i++ {
		dx := movements[i].X - movements[i-1].X
		dy := movements[i].Y - movements[i-1].Y
		distance := math.Sqrt(dx*dx + dy*dy)
		distances.append(distance)
	}
	
	if len(distances) == 0 {
		return 0.0
	}
	
	// Calculate mean
	var sum float64
	for _, d := range distances {
		sum += d
	}
	mean := sum / float64(len(distances))
	
	// Calculate variance
	var variance float64
	for _, d := range distances {
		variance += math.Pow(d-mean, 2)
	}
	variance /= float64(len(distances))
	
	// Normalized entropy
	return variance / (mean*mean + 1)
}

func (ba *BehavioralAnalyzer) calculateAverageMouseSpeed(movements []MouseEvent) float64 {
	if len(movements) < 2 {
		return 0.0
	}
	
	var totalDistance float64
	var totalTime int64
	
	for i := 1; i < len(movements); i++ {
		dx := movements[i].X - movements[i-1].X
		dy := movements[i].Y - movements[i-1].Y
		distance := math.Sqrt(dx*dx + dy*dy)
		time := movements[i].Timestamp - movements[i-1].Timestamp
		
		totalDistance += distance
		totalTime += time
	}
	
	if totalTime > 0 {
		return (totalDistance / float64(totalTime)) * 1000 // pixels per second
	}
	
	return 0.0
}

func (ba *BehavioralAnalyzer) calculateTypingSpeed(events []KeyboardEvent) float64 {
	if len(events) < 2 {
		return 0.0
	}
	
	var keyPresses []KeyboardEvent
	for _, event := range events {
		if event.Type == "keydown" && len(event.Key) == 1 {
			keyPresses = append(keyPresses, event)
		}
	}
	
	if len(keyPresses) < 2 {
		return 0.0
	}
	
	totalTime := keyPresses[len(keyPresses)-1].Timestamp - keyPresses[0].Timestamp
	if totalTime > 0 {
		return (float64(len(keyPresses)) / float64(totalTime)) * 1000 // characters per second
	}
	
	return 0.0
}

// ParseBehavioralData parses JSON behavioral data
func (ba *BehavioralAnalyzer) ParseBehavioralData(jsonData string) (*BehavioralData, error) {
	var data BehavioralData
	err := json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

