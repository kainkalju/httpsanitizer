package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	valid "github.com/asaskevich/govalidator"
	"github.com/julienschmidt/httprouter"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

// Global koanf instance. Use "." as the key path delimiter. This can be "/" or any character.
var k = koanf.New(".")

// auditLogger is the structured JSON audit log writer. nil = audit logging disabled.
var auditLogger *log.Logger

// auditKey is the context key for the per-request audit event accumulator.
type auditKey struct{}

// auditEvent records a single sanitization detection without including the payload value.
type auditEvent struct {
	Rule     string `json:"rule"`
	Field    string `json:"field,omitempty"`
	Location string `json:"location"` // "query", "post", "body", "header", "ip"
}

// auditLog accumulates sanitization events during a single request.
type auditLog struct {
	events []auditEvent
}

func (a *auditLog) add(rule, field, location string) {
	a.events = append(a.events, auditEvent{Rule: rule, Field: field, Location: location})
}

// auditWriter wraps http.ResponseWriter to capture the response status code so it
// can be included in the audit log entry written after ServeHTTP returns.
type auditWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *auditWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// blockKey is the context key used to carry a blockFlag through the request pipeline.
type blockKey struct{}

// blockFlag accumulates violation signals from sanitizing functions.
// A non-nil, triggered flag causes blockingTransport to return a 403 instead of
// forwarding the request to the upstream.
type blockFlag struct {
	triggered bool
	reason    string
}

func (f *blockFlag) trigger(reason string) {
	if !f.triggered {
		f.triggered = true
		f.reason = reason
	}
}

// blockingTransport wraps the default RoundTripper. When a blockFlag in the
// request context has been triggered it returns a synthetic 403 response without
// ever contacting the upstream server.
type blockingTransport struct{ base http.RoundTripper }

func (t *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if flag, ok := req.Context().Value(blockKey{}).(*blockFlag); ok && flag.triggered {
		log.Printf("BLOCK: %s %s%s — %s", req.Method, req.Host, req.URL.RequestURI(), flag.reason)
		body := "Forbidden\n"
		return &http.Response{
			StatusCode:    http.StatusForbidden,
			Status:        "403 Forbidden",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          ioutil.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       req,
		}, nil
	}
	return t.base.RoundTrip(req)
}

func main() {
	configFile := flag.String("config", "config.yaml", "path to the YAML configuration file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var execCmd string = ""
	var upstreamURL = "http://127.0.0.1:9000/"
	var serverAddr string = ":8080"
	var serverReadTimeout time.Duration = 10
	var serverWriteTimeout time.Duration = 10
	var serverIdleTimeout time.Duration = 20
	var serverMaxHeaderBytes int = 4096

	// Load YAML config.
	cfg := file.Provider(*configFile)
	if err := k.Load(cfg, yaml.Parser()); err != nil {
		log.Fatalf("error loading config: %v", err)
	}
	// Overwrite default settings with YAML config
	if k.Exists("upstream.url") {
		upstreamURL = k.String("upstream.url")
	}
	if k.Exists("upstream.exec") {
		execCmd = k.String("upstream.exec")
	}
	if k.Exists("server.addr") {
		serverAddr = k.String("server.addr")
	}
	if k.Exists("server.readTimeout") {
		serverReadTimeout = time.Duration(k.Int("server.readTimeout"))
	}
	if k.Exists("server.writeTimeout") {
		serverWriteTimeout = time.Duration(k.Int("server.writeTimeout"))
	}
	if k.Exists("server.idleTimeout") {
		serverIdleTimeout = time.Duration(k.Int("server.idleTimeout"))
	}
	if k.Exists("server.maxHeaderBytes") {
		serverMaxHeaderBytes = k.Int("server.maxHeaderBytes")
	}
	// Initialize audit logger (once at startup; hot-reload does not change the destination).
	if k.Exists("audit_log") {
		dest := k.String("audit_log")
		var w io.Writer
		if dest == "true" || dest == "stdout" {
			w = os.Stdout
		} else {
			f, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("audit_log: cannot open %q: %v", dest, err)
			}
			w = f
		}
		auditLogger = log.New(w, "", 0)
		log.Printf("audit logging enabled → %s", dest)
	}

	// Watch the file and get a callback on change. The callback can do whatever,
	// like re-load the configuration.
	// File provider always returns a nil `event`.
	cfg.Watch(func(event interface{}, err error) {
		if err != nil {
			log.Printf("watch error: %v", err)
			return
		}

		log.Println("config change detected. Reloading ...")
		k.Load(cfg, yaml.Parser())
		k.Print()
	})

	if execCmd != "" {
		cmd := execProgram(execCmd)
		// wait `cmd` until it finishes when exit
		defer cmd.Wait()
		// monitoting program in a goroutine
		go func() {
			for {
				cmd.Wait()
				log.Println("WARN: background process exited.")
				// Fix #5: sleep before restarting to prevent tight CPU-exhausting loop
				time.Sleep(2 * time.Second)
				// try to start again
				cmd = execProgram(execCmd)
			}
		}()
	}

	router := httprouter.New()
	origin, _ := url.Parse(upstreamURL)
	path := "/*catchall"

	reverseProxy := httputil.NewSingleHostReverseProxy(origin)
	// Fix #7: capture default director to preserve hop-by-hop header stripping and X-Forwarded-For handling
	defaultDirector := reverseProxy.Director

	// blockingTransport intercepts requests flagged for blocking before they reach upstream.
	reverseProxy.Transport = &blockingTransport{base: http.DefaultTransport}

	reverseProxy.Director = func(req *http.Request) {
		// Call default director first: strips hop-by-hop headers, sets X-Forwarded-For, sets URL scheme/host
		defaultDirector(req)

		// Extract block flag injected by the route handler (nil when block_on_detect is off).
		flag, _ := req.Context().Value(blockKey{}).(*blockFlag)

		switch m := req.Method; m {
		case "POST", "PUT", "PATCH":
			sanitizingGET(req, k, flag)
			sanitizingJSONBody(req, k, flag)
			sanitizingXMLBody(req, k, flag)
			sanitizingPOST(req, k, flag)
		default:
			sanitizingGET(req, k, flag)
		}

		sanitizingIncomingCookies(req, k)
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", origin.Host)
		sanitizingIncomingHeaders(req, k, flag)
	}

	reverseProxy.ModifyResponse = func(res *http.Response) error {
		sanitizingOutgoingHeaders(res, k)
		return nil
	}

	// Single handler shared by all methods. Wraps the ResponseWriter to capture
	// the status code, injects audit/block context values, and writes a structured
	// audit log entry on every exit path.
	handle := func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		startTime := time.Now()
		aw := &auditWriter{ResponseWriter: w}

		if !checkIPAccess(r.RemoteAddr, k) {
			log.Printf("ACCESS DENIED: %s %s %s%s", r.RemoteAddr, r.Method, r.Host, r.RequestURI)
			http.Error(aw, "Forbidden", http.StatusForbidden)
			al := &auditLog{}
			al.add("access_control", "", "ip")
			writeAuditLog(r, aw.status, time.Since(startTime), al, true, false)
			log.Printf("from: %s %s %s%s duration: %s\n", r.RemoteAddr, r.Method, r.Host, r.RequestURI, time.Since(startTime))
			return
		}
		if maxBodyBytes := int64(k.Int("server.maxBodyBytes")); maxBodyBytes > 0 && r.Body != nil {
			body, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
			if err != nil {
				log.Printf("REQUEST TOO LARGE: %s %s %s%s", r.RemoteAddr, r.Method, r.Host, r.RequestURI)
				http.Error(aw, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				al := &auditLog{}
				al.add("max_body_bytes", "", "body")
				writeAuditLog(r, aw.status, time.Since(startTime), al, false, false)
				log.Printf("from: %s %s %s%s duration: %s\n", r.RemoteAddr, r.Method, r.Host, r.RequestURI, time.Since(startTime))
				return
			}
			r.Body = ioutil.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}

		ctx := r.Context()
		var al *auditLog
		if auditLogger != nil {
			al = &auditLog{}
			ctx = context.WithValue(ctx, auditKey{}, al)
		}
		if k.Bool("block_on_detect") {
			ctx = context.WithValue(ctx, blockKey{}, &blockFlag{})
		}
		r = r.WithContext(ctx)

		reverseProxy.ServeHTTP(aw, r)

		bf, _ := r.Context().Value(blockKey{}).(*blockFlag)
		writeAuditLog(r, aw.status, time.Since(startTime), al, false, bf != nil && bf.triggered)
		log.Printf("from: %s %s %s%s duration: %s\n", r.RemoteAddr, r.Method, r.Host, r.RequestURI, time.Since(startTime))
	}

	for _, method := range []string{"HEAD", "GET", "POST", "PUT", "DELETE"} {
		router.Handle(method, path, handle)
	}

	server := &http.Server{
		Addr:           serverAddr,
		Handler:        router,
		ReadTimeout:    serverReadTimeout * time.Second,
		WriteTimeout:   serverWriteTimeout * time.Second,
		IdleTimeout:    serverIdleTimeout * time.Second,
		MaxHeaderBytes: serverMaxHeaderBytes,
	}
	log.Println("Starting the httpsanitizer reverse proxy server")
	log.Fatal(server.ListenAndServe())
}

func execProgram(execCmd string) *exec.Cmd {
	args := strings.Split(execCmd, " ")

	// setup background command
	cmd := &exec.Cmd{
		Path:   args[0],
		Args:   args,
		Stdout: os.Stdout,
		Stderr: os.Stdout,
	}
	// run `cmd` in background
	cmd.Start()

	log.Println("Stated background process:", execCmd)

	return cmd
}

// writeAuditLog emits a single JSON-lines audit entry to auditLogger.
// No-op when auditLogger is nil. Payload values are never included.
func writeAuditLog(r *http.Request, status int, duration time.Duration, al *auditLog, denied bool, blocked bool) {
	if auditLogger == nil {
		return
	}
	if status == 0 {
		status = http.StatusOK
	}
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	var events []auditEvent
	if al != nil {
		events = al.events
	}
	entry := struct {
		Timestamp  string       `json:"ts"`
		ClientIP   string       `json:"client_ip"`
		Method     string       `json:"method"`
		Host       string       `json:"host"`
		Path       string       `json:"path"`
		Status     int          `json:"status"`
		DurationMs int64        `json:"duration_ms"`
		Denied     bool         `json:"denied,omitempty"`
		Blocked    bool         `json:"blocked,omitempty"`
		Events     []auditEvent `json:"events,omitempty"`
	}{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		ClientIP:   clientIP,
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.RequestURI(),
		Status:     status,
		DurationMs: duration.Milliseconds(),
		Denied:     denied,
		Blocked:    blocked,
		Events:     events,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		log.Printf("audit log marshal error: %v", err)
		return
	}
	auditLogger.Println(string(b))
}

// checkIPAccess returns true if the remote address is permitted by the
// access_control config. Deny rules are evaluated before allow rules.
//
//   - If only access_control.deny is set: block matching IPs, allow the rest.
//   - If only access_control.allow is set: allow matching IPs, block the rest.
//   - If both are set: deny-list is checked first; an IP that is not denied must
//     still appear in the allow-list to pass.
//   - If neither is set: all IPs are allowed.
func checkIPAccess(remoteAddr string, k *koanf.Koanf) bool {
	hasDeny := k.Exists("access_control.deny")
	hasAllow := k.Exists("access_control.allow")
	if !hasDeny && !hasAllow {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		log.Printf("access_control: cannot parse remote IP %q; denying", remoteAddr)
		return false
	}

	if hasDeny {
		for _, entry := range k.Strings("access_control.deny") {
			if matchesCIDR(ip, entry) {
				return false
			}
		}
	}

	if hasAllow {
		for _, entry := range k.Strings("access_control.allow") {
			if matchesCIDR(ip, entry) {
				return true
			}
		}
		return false
	}

	return true
}

// matchesCIDR reports whether ip falls within the given CIDR range or equals
// the given bare IP address.
func matchesCIDR(ip net.IP, entry string) bool {
	if _, network, err := net.ParseCIDR(entry); err == nil {
		return network.Contains(ip)
	}
	if other := net.ParseIP(entry); other != nil {
		return ip.Equal(other)
	}
	log.Printf("access_control: invalid CIDR/IP %q in config; skipping", entry)
	return false
}

func sanitizingOutgoingHeaders(res *http.Response, k *koanf.Koanf) {

	// Apply only/del first to filter upstream headers, then set proxy-injected
	// headers last so they are never subject to the upstream allowlist.
	if k.Exists("http_header_out.only") {
		onlySet := make(map[string]bool)
		for _, name := range k.Strings("http_header_out.only") {
			onlySet[name] = true
		}
		for n := range res.Header {
			if !onlySet[n] {
				res.Header.Del(n)
				log.Println("remove header: ", n)
			}
		}
	}
	if k.Exists("http_header_out.del") {
		for _, name := range k.Strings("http_header_out.del") {
			res.Header.Del(name)
			log.Println("remove header: ", name)
		}
	}
	if k.Exists("http_header_out.set") {
		for _, name := range k.MapKeys("http_header_out.set") {
			value := k.String("http_header_out.set." + name)
			res.Header.Set(name, value)
		}
	}

}

func sanitizingIncomingHeaders(req *http.Request, k *koanf.Koanf, flag *blockFlag) {

	if k.Exists("http_header_in.set") {
		for _, name := range k.MapKeys("http_header_in.set") {
			value := k.String("http_header_in.set." + name)
			req.Header.Set(name, value)
			// log.Println("set header: ", name, value)
		}
	}
	if k.Exists("http_header_in.del") {
		for _, name := range k.Strings("http_header_in.del") {
			req.Header.Del(name)
			log.Println("remove header: ", name)
		}
	}
	if k.Exists("http_header_in.only") {
		var match bool
		for n := range req.Header {
			match = false
			for _, name := range k.Strings("http_header_in.only") {
				if name == n {
					match = true
				}
			}
			if match == false {
				req.Header.Del(n)
				log.Println("remove header: ", n)
			}
		}
	}
	if k.Exists("sanitize_http_headers") {
		p := "sanitize_http_headers"
		al, _ := req.Context().Value(auditKey{}).(*auditLog)
		// Fix #4: removed url.QueryUnescape — HTTP headers are not URL-encoded;
		// unescaping caused invalid % sequences (e.g. "100% genuine") to wipe the header.
		// Fix #6: iterate all values per header name instead of Get/Set (which truncates multi-value headers).
		for name, values := range req.Header {
			sanitized := make([]string, 0, len(values))
			for _, value := range values {
				original := value
				value = validateMaxLen(k, p, value)
				value = validateStripChars(k, p, value)
				value = validateStripQuotation(k, p, value)
				value = validateStripBinary(k, p, value)
				value = validateStripHTML(k, p, value)
				value = validateStripSQLia(k, p, value)
				if value != original {
					if flag != nil {
						flag.trigger(fmt.Sprintf("header %q violated sanitize_http_headers policy", name))
					}
					if al != nil {
						al.add("sanitize_http_headers", name, "header")
					}
				}
				sanitized = append(sanitized, value)
			}
			req.Header[name] = sanitized
		}
	}

}

func sanitizingIncomingCookies(req *http.Request, k *koanf.Koanf) {

	// Work on a slice so set/del/only transformations compose correctly
	// without intermediate header clear/restore cycles losing cookies.
	cookies := req.Cookies()

	if k.Exists("http_cookie_in.set") {
		// Build index for O(1) override detection
		idx := make(map[string]int, len(cookies))
		for i, c := range cookies {
			idx[c.Name] = i
		}
		for _, name := range k.MapKeys("http_cookie_in.set") {
			value := k.String("http_cookie_in.set." + name)
			c := &http.Cookie{Name: name, Value: value}
			if i, exists := idx[name]; exists {
				cookies[i] = c
			} else {
				idx[name] = len(cookies)
				cookies = append(cookies, c)
			}
			log.Println("set cookie: ", name, value)
		}
	}

	if k.Exists("http_cookie_in.del") {
		delSet := make(map[string]bool)
		for _, name := range k.Strings("http_cookie_in.del") {
			delSet[name] = true
		}
		filtered := cookies[:0]
		for _, c := range cookies {
			if delSet[c.Name] {
				log.Println("remove cookie: ", c.Name)
			} else {
				filtered = append(filtered, c)
			}
		}
		cookies = filtered
	}

	if k.Exists("http_cookie_in.only") {
		onlySet := make(map[string]bool)
		for _, name := range k.Strings("http_cookie_in.only") {
			onlySet[name] = true
		}
		filtered := cookies[:0]
		for _, c := range cookies {
			if onlySet[c.Name] {
				filtered = append(filtered, c)
			} else {
				log.Println("remove cookie: ", c.Name)
			}
		}
		cookies = filtered
	}

	req.Header.Del("Cookie")
	for _, c := range cookies {
		req.AddCookie(c)
	}

}

func sanitizingGET(req *http.Request, k *koanf.Koanf, flag *blockFlag) {
	al, _ := req.Context().Value(auditKey{}).(*auditLog)
	data := url.Values{}
	for name, values := range req.URL.Query() {
		for _, value := range values {
			p := "form_params." + name
			if k.Exists(p) == false {
				if k.Exists("form_params._defaults_") {
					p = "form_params._defaults_"
				}
			}
			if k.Exists(p) {
				//log.Printf("get sanitizing: %v\n", name)
				original := value
				switch t := k.String(p + ".type"); t {
				case "text":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripQuotation(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validateStripHTML(k, p, value)
					value = validateStripSQLia(k, p, value)
				case "numeric":
					value = validateNumeric(value)
				case "email":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validateEmail(value)
				case "ip":
					value = validateIP(value)
				case "url":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validateURL(value)
				case "path":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validatePath(value)
				case "filename":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validateFilePath(value)
				case "unixtime":
					value = validateUnixTime(value)
				case "absent":
					value = ""
				default:
				}
				if value != original {
					if flag != nil {
						flag.trigger(fmt.Sprintf("query param %q violated form_params policy", name))
					}
					if al != nil {
						al.add("form_params", name, "query")
					}
				}
			}
			if k.Exists("sanitize_form_names") {
				name = validateFormName(k, "sanitize_form_names", name)
			}
			data.Add(name, value)
		}
	}

	req.URL.RawQuery = data.Encode()
}

func sanitizingPOST(req *http.Request, k *koanf.Koanf, flag *blockFlag) {
	al, _ := req.Context().Value(auditKey{}).(*auditLog)
	// Fix #2: only process application/x-www-form-urlencoded bodies.
	// For any other Content-Type (multipart/form-data, application/json, etc.),
	// ParseForm silently does nothing, then the original body would be forwarded unsanitized.
	// If form_params rules are configured, discard non-urlencoded bodies entirely,
	// unless a dedicated body sanitizer already handled this Content-Type.
	ct := strings.TrimSpace(req.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if k.Exists("form_params") {
			isJSON := strings.HasPrefix(ct, "application/json")
			isXML := strings.HasPrefix(ct, "text/xml") || strings.HasPrefix(ct, "application/xml")
			if (isJSON && k.Exists("sanitize_json_body")) || (isXML && k.Exists("sanitize_xml_body")) {
				// Already sanitized by the dedicated handler above; leave body as-is.
				return
			}
			log.Printf("sanitizingPOST: unsupported Content-Type %q; discarding body to enforce form_params rules", ct)
			req.Body = ioutil.NopCloser(bytes.NewBuffer(nil))
			req.ContentLength = 0
		}
		return
	}

	data := url.Values{}
	req.ParseForm()
	if len(req.PostForm) == 0 {
		return
	}
	for name, values := range req.PostForm {
		for _, value := range values {
			p := "form_params." + name
			if k.Exists(p) == false {
				if k.Exists("form_params._defaults_") {
					p = "form_params._defaults_"
				}
			}
			if k.Exists(p) {
				//log.Printf("post sanitizing: %v\n", name)
				original := value
				switch t := k.String(p + ".type"); t {
				case "text":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripQuotation(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validateStripHTML(k, p, value)
					value = validateStripSQLia(k, p, value)
				case "numeric":
					value = validateNumeric(value)
				case "email":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validateEmail(value)
				case "ip":
					value = validateIP(value)
				case "url":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validateURL(value)
				case "path":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validatePath(value)
				case "filename":
					value = validateMaxLen(k, p, value)
					value = validateStripChars(k, p, value)
					value = validateStripBinary(k, p, value)
					value = validateFilePath(value)
				case "unixtime":
					value = validateUnixTime(value)
				case "absent":
					value = ""
				default:
				}
				if value != original {
					if flag != nil {
						flag.trigger(fmt.Sprintf("POST param %q violated form_params policy", name))
					}
					if al != nil {
						al.add("form_params", name, "post")
					}
				}
			}
			if k.Exists("sanitize_form_names") {
				name = validateFormName(k, "sanitize_form_names", name)
			}
			data.Add(name, value)
		}
	}

	newBody := data.Encode()
	req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(newBody)))
	req.ContentLength = int64(len(newBody))
}

// sanitizeBodyField applies form_params rules for a named field.
// Falls back to _defaults_ when no per-field rule exists.
// flag and al may be nil; when non-nil they record violations for blocking and audit logging.
func sanitizeBodyField(k *koanf.Koanf, fieldName string, value string, flag *blockFlag, al *auditLog) string {
	p := "form_params." + fieldName
	if !k.Exists(p) {
		if k.Exists("form_params._defaults_") {
			p = "form_params._defaults_"
		}
	}
	if !k.Exists(p) {
		return value
	}
	original := value
	switch t := k.String(p + ".type"); t {
	case "text":
		value = validateMaxLen(k, p, value)
		value = validateStripChars(k, p, value)
		value = validateStripQuotation(k, p, value)
		value = validateStripBinary(k, p, value)
		value = validateStripHTML(k, p, value)
		value = validateStripSQLia(k, p, value)
	case "numeric":
		value = validateNumeric(value)
	case "email":
		value = validateMaxLen(k, p, value)
		value = validateStripChars(k, p, value)
		value = validateStripBinary(k, p, value)
		value = validateEmail(value)
	case "ip":
		value = validateIP(value)
	case "url":
		value = validateMaxLen(k, p, value)
		value = validateStripChars(k, p, value)
		value = validateStripBinary(k, p, value)
		value = validateURL(value)
	case "path":
		value = validateMaxLen(k, p, value)
		value = validateStripChars(k, p, value)
		value = validateStripBinary(k, p, value)
		value = validatePath(value)
	case "filename":
		value = validateMaxLen(k, p, value)
		value = validateStripChars(k, p, value)
		value = validateStripBinary(k, p, value)
		value = validateFilePath(value)
	case "unixtime":
		value = validateUnixTime(value)
	case "absent":
		value = ""
	}
	if value != original {
		if flag != nil {
			flag.trigger(fmt.Sprintf("body field %q violated form_params policy", fieldName))
		}
		if al != nil {
			al.add("form_params", fieldName, "body")
		}
	}
	return value
}

// sanitizingJSONBody sanitizes string values in a JSON request body.
// Enabled by setting sanitize_json_body: true in config.
// Field-level rules are sourced from form_params (with _defaults_ fallback).
func sanitizingJSONBody(req *http.Request, k *koanf.Koanf, flag *blockFlag) {
	if !k.Exists("sanitize_json_body") {
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(req.Header.Get("Content-Type")), "application/json") {
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		log.Printf("sanitizingJSONBody: read error: %v; discarding body", err)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(nil))
		req.ContentLength = 0
		return
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("sanitizingJSONBody: invalid JSON, discarding body: %v", err)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(nil))
		req.ContentLength = 0
		return
	}

	al, _ := req.Context().Value(auditKey{}).(*auditLog)
	data = sanitizeJSONNode(k, "", data, flag, al)

	sanitized, err := json.Marshal(data)
	if err != nil {
		log.Printf("sanitizingJSONBody: marshal error: %v; forwarding original body", err)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		req.ContentLength = int64(len(body))
		return
	}

	req.Body = ioutil.NopCloser(bytes.NewBuffer(sanitized))
	req.ContentLength = int64(len(sanitized))
}

// sanitizeJSONNode recursively walks a decoded JSON value and sanitizes all strings.
// Object keys are used as field names for form_params lookup.
// Array items inherit the field name of their parent array.
func sanitizeJSONNode(k *koanf.Koanf, key string, val interface{}, flag *blockFlag, al *auditLog) interface{} {
	switch v := val.(type) {
	case string:
		return sanitizeBodyField(k, key, v, flag, al)
	case map[string]interface{}:
		for field, child := range v {
			v[field] = sanitizeJSONNode(k, field, child, flag, al)
		}
		return v
	case []interface{}:
		for i, item := range v {
			v[i] = sanitizeJSONNode(k, key, item, flag, al)
		}
		return v
	default:
		// numbers, booleans, null — no sanitization needed
		return val
	}
}

// sanitizingXMLBody sanitizes character data and attribute values in an XML request body.
// Enabled by setting sanitize_xml_body: true in config.
// Field-level rules are sourced from form_params (with _defaults_ fallback).
func sanitizingXMLBody(req *http.Request, k *koanf.Koanf, flag *blockFlag) {
	if !k.Exists("sanitize_xml_body") {
		return
	}
	ct := strings.TrimSpace(req.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "text/xml") && !strings.HasPrefix(ct, "application/xml") {
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		log.Printf("sanitizingXMLBody: read error: %v; discarding body", err)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(nil))
		req.ContentLength = 0
		return
	}

	al, _ := req.Context().Value(auditKey{}).(*auditLog)
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var buf bytes.Buffer
	encoder := xml.NewEncoder(&buf)
	var elementStack []string

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("sanitizingXMLBody: invalid XML, discarding body: %v", err)
			req.Body = ioutil.NopCloser(bytes.NewBuffer(nil))
			req.ContentLength = 0
			return
		}

		switch t := tok.(type) {
		case xml.StartElement:
			elementStack = append(elementStack, t.Name.Local)
			for i, attr := range t.Attr {
				t.Attr[i].Value = sanitizeBodyField(k, attr.Name.Local, attr.Value, flag, al)
			}
			encoder.EncodeToken(t)
		case xml.EndElement:
			if len(elementStack) > 0 {
				elementStack = elementStack[:len(elementStack)-1]
			}
			encoder.EncodeToken(t)
		case xml.CharData:
			currentElement := ""
			if len(elementStack) > 0 {
				currentElement = elementStack[len(elementStack)-1]
			}
			// Copy: the underlying byte slice is reused across Token() calls.
			data := make(xml.CharData, len(t))
			copy(data, t)
			sanitized := sanitizeBodyField(k, currentElement, string(data), flag, al)
			encoder.EncodeToken(xml.CharData(sanitized))
		default:
			encoder.EncodeToken(tok)
		}
	}

	if err := encoder.Flush(); err != nil {
		log.Printf("sanitizingXMLBody: flush error: %v; forwarding original body", err)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		req.ContentLength = int64(len(body))
		return
	}

	sanitized := buf.Bytes()
	req.Body = ioutil.NopCloser(bytes.NewBuffer(sanitized))
	req.ContentLength = int64(len(sanitized))
}

func validateFormName(k *koanf.Koanf, name string, value string) string {
	value = validateStripChars(k, name, value)
	value = validateStripQuotation(k, name, value)
	value = validateStripBinary(k, name, value)
	value = validateStripHTML(k, name, value)
	return value
}

func validateMaxLen(k *koanf.Koanf, name string, value string) string {

	if k.Exists(name + ".maxlen") {
		maxlen := k.Int(name + ".maxlen")
		if len(value) > maxlen {
			value = value[:maxlen]
		}
	}

	return value
}

func validateStripChars(k *koanf.Koanf, name string, value string) string {

	if k.Exists(name + ".strip_chars") {
		filter := k.String(name + ".strip_chars")
		value = valid.BlackList(value, filter)
	}

	return value
}

func validateStripQuotation(k *koanf.Koanf, name string, value string) string {

	if k.Exists(name + ".strip_quotation") {
		value = valid.BlackList(value, "\"")
	}

	return value
}

func validateStripBinary(k *koanf.Koanf, name string, value string) string {

	if k.Exists(name + ".strip_binary") {
		value = valid.StripLow(value, true)
		value = valid.Trim(value, "")
	}

	return value
}

func validateStripHTML(k *koanf.Koanf, name string, value string) string {

	if k.Exists(name + ".strip_html") {
		value = valid.RemoveTags(value)
	}

	return value
}

func validateStripSQLia(k *koanf.Koanf, name string, value string) string {
	if k.Exists(name + ".strip_sqlia") {
		// Fix #3: detect individual dangerous SQL keywords — no longer requiring keyword pairs
		// (old logic missed UNION SELECT, DELETE without FROM, bare DROP, etc.).
		// Keywords are matched as whole words to reduce false positives.
		s := strings.ToUpper(value)
		dangerous := []string{
			"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
			"RENAME", "UNION", "EXEC", "EXECUTE", "DECLARE", "WAITFOR",
		}
		match := false
		for _, kw := range dangerous {
			offset := 0
			// Loop to check all occurrences of the keyword
			for {
				idx := strings.Index(s[offset:], kw)
				if idx < 0 {
					break // No more occurrences in this keyword
				}
				realIdx := offset + idx

				// Verify it is a whole word (not embedded inside another identifier)
				before := realIdx == 0 || !isAlphaNum(rune(s[realIdx-1]))
				after := realIdx+len(kw) >= len(s) || !isAlphaNum(rune(s[realIdx+len(kw)]))

				if before && after {
					match = true
					break
				}

				// Move past this occurrence
				offset = realIdx + len(kw)
			}

			if match {
				break
			}
		}
		if match {
			log.Printf("strip_sqlia matches: %v", value)
			value = valid.ReplacePattern(value,
				`(?i)\b(select|insert|update|delete|drop|truncate|rename|union|exec|execute|declare|waitfor)\b`,
				"xxxxxx")
		}
	}

	return value
}

func isAlphaNum(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
}

func validateNumeric(value string) string {
	value = valid.WhiteList(value, "1234567890,.")
	return value
}

func validateIP(value string) string {
	if valid.IsIP(value) == false {
		log.Printf("not valid IP: %v", value)
		value = ""
	}
	return value
}

func validateUnixTime(value string) string {
	if valid.IsUnixTime(value) == false {
		log.Printf("not valid unixtime: %v", value)
		value = ""
	}
	return value
}

func validateEmail(value string) string {
	if valid.IsEmail(value) == false {
		log.Printf("not valid e-mail: %v", value)
		value = ""
	}
	return value
}

func validateURL(value string) string {
	if valid.IsRequestURL(value) == false {
		log.Printf("not valid URL: %v", value)
		value = ""
	}
	return value
}

func validatePath(value string) string {
	if valid.IsRequestURI(value) == false {
		log.Printf("not valid Path: %v", value)
		value = ""
	}
	return value
}

func validateFilePath(value string) string {
	err, _ := valid.IsFilePath(value)
	if err == false {
		value = valid.SafeFileName(value)
	}
	return value
}
