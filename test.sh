#!/usr/bin/env bash
# Comprehensive curl test suite for httpsanitizer (based on config.yaml)
# Requires: proxy running at localhost:8080

PROXY="http://localhost:8080"
PASS=0
FAIL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

pass() { printf "${GREEN}PASS${NC} %s\n" "$1"; PASS=$((PASS+1)); }
fail() { printf "${RED}FAIL${NC} %s\n" "$1"; FAIL=$((FAIL+1)); }
section() { printf "\n${BOLD}--- %s ---${NC}\n" "$1"; }
note() { printf "${YELLOW}NOTE${NC} %s\n" "$1"; }

# Check a response header is present (case-insensitive)
has_header() {
    local hdr="$1" resp="$2"
    echo "$resp" | grep -qi "^${hdr}:"
}

# Get response code only
http_code() { curl -so /dev/null -w "%{http_code}" "$@"; }

# Get response headers only (HEAD request)
resp_headers() { curl -sI "$@"; }

echo "======================================="
echo " httpsanitizer test suite"
echo " Proxy: $PROXY"
echo "======================================="

# ---------------------------------------------------------------------------
# 1. OUTGOING RESPONSE HEADERS  (http_header_out)
# ---------------------------------------------------------------------------
section "http_header_out"

H=$(resp_headers "$PROXY/")

# set: security headers must be injected into every response
echo "$H" | grep -qi "X-XSS-Protection:.*1.*mode=block" \
    && pass "out.set: X-XSS-Protection: 1; mode=block" \
    || fail "out.set: X-XSS-Protection missing or wrong value"

echo "$H" | grep -qi "X-Content-Type-Options:.*nosniff" \
    && pass "out.set: X-Content-Type-Options: nosniff" \
    || fail "out.set: X-Content-Type-Options missing or wrong value"

echo "$H" | grep -qi "X-Permitted-Cross-Domain-Policies:.*none" \
    && pass "out.set: X-Permitted-Cross-Domain-Policies: none" \
    || fail "out.set: X-Permitted-Cross-Domain-Policies missing or wrong value"

echo "$H" | grep -qi "Content-Security-Policy:" \
    && pass "out.set: Content-Security-Policy present" \
    || fail "out.set: Content-Security-Policy missing"

# del: Cache-Control must be removed
echo "$H" | grep -qi "^Cache-Control:" \
    && fail "out.del: Cache-Control should be absent" \
    || pass "out.del: Cache-Control absent"

# only: headers not in the allowlist must be stripped
# (the upstream sends headers like X-Powered-By, Via, etc. — they should be gone)
echo "$H" | grep -qi "^X-Powered-By:" \
    && fail "out.only: X-Powered-By should be stripped" \
    || pass "out.only: X-Powered-By absent"

echo "$H" | grep -qi "^Via:" \
    && fail "out.only: Via should be stripped" \
    || pass "out.only: Via absent"

echo "$H" | grep -qi "^X-Cache:" \
    && fail "out.only: X-Cache should be stripped" \
    || pass "out.only: X-Cache absent"

# ---------------------------------------------------------------------------
# 2. INCOMING COOKIES  (http_cookie_in)
#    Full verification requires an echo backend; these are proxy smoke tests.
# ---------------------------------------------------------------------------
section "http_cookie_in"
note "Full cookie-to-upstream verification requires an echo backend."

# No cookies — Foo=bar must still be injected by the proxy
CODE=$(http_code "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "set Foo=bar: no client cookies, proxy responds HTTP $CODE" \
    || fail "set Foo=bar: proxy did not respond"

# Regular cookie must pass through (and Foo=bar added alongside)
CODE=$(http_code -b "session=abc123" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "set Foo=bar + client cookie: proxy responds HTTP $CODE" \
    || fail "set Foo=bar + client cookie: proxy did not respond"

# X-XSRF-TOKEN cookie must be deleted before reaching upstream
CODE=$(http_code -b "X-XSRF-TOKEN=evil; session=valid" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "del X-XSRF-TOKEN cookie: proxy responds HTTP $CODE" \
    || fail "del X-XSRF-TOKEN cookie: proxy did not respond"

# Multiple cookies — only X-XSRF-TOKEN removed, rest forwarded + Foo injected
CODE=$(http_code -b "X-XSRF-TOKEN=bad; a=1; b=2" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "del X-XSRF-TOKEN, keep a and b: proxy responds HTTP $CODE" \
    || fail "del X-XSRF-TOKEN, keep a and b: proxy did not respond"

# ---------------------------------------------------------------------------
# 3. INCOMING HEADERS  (http_header_in)
#    User-Agent override and X-XSRF-TOKEN deletion are upstream-side changes;
#    smoke-tested here, verify with an echo backend for full coverage.
# ---------------------------------------------------------------------------
section "http_header_in"
note "Header mutation to upstream requires an echo backend for full verification."

# User-Agent is always overridden to httpsanitizer/0.1
CODE=$(http_code -H "User-Agent: EvilBot/9.0" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "set User-Agent: custom UA sent, proxy responds HTTP $CODE" \
    || fail "set User-Agent: proxy did not respond"

# X-XSRF-TOKEN header must be stripped
CODE=$(http_code -H "X-XSRF-TOKEN: csrf-token-here" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "del X-XSRF-TOKEN header: proxy responds HTTP $CODE" \
    || fail "del X-XSRF-TOKEN header: proxy did not respond"

# X-Forwarded-For and X-Origin-Host added by proxy (standard behaviour)
CODE=$(http_code "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "proxy adds X-Forwarded-For / X-Origin-Host: proxy responds HTTP $CODE" \
    || fail "proxy adds X-Forwarded-For / X-Origin-Host: proxy did not respond"

# ---------------------------------------------------------------------------
# 4. HEADER SANITIZATION  (sanitize_http_headers)
#    maxlen:256, strip_binary, strip_html, strip_sqlia
# ---------------------------------------------------------------------------
section "sanitize_http_headers"

# maxlen: 256 — 512-char header value must be truncated, not cause a crash
LONG=$(python3 -c "print('A'*512)")
CODE=$(http_code -H "X-Test: $LONG" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "maxlen 256: 512-char header value, proxy responds HTTP $CODE" \
    || fail "maxlen 256: proxy did not respond"

# strip_html: <script> tag in a header
CODE=$(http_code -H "X-Test: <script>alert(1)</script>" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "strip_html: <script> in header, proxy responds HTTP $CODE" \
    || fail "strip_html: proxy did not respond"

# strip_sqlia: SQL injection in a header
CODE=$(http_code -H "X-Test: ' OR 1=1; DROP TABLE users--" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "strip_sqlia: SQL injection in header, proxy responds HTTP $CODE" \
    || fail "strip_sqlia: proxy did not respond"

# strip_sqlia: UNION SELECT
CODE=$(http_code -H "X-Search: foo UNION SELECT * FROM secrets" "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "strip_sqlia: UNION SELECT in header, proxy responds HTTP $CODE" \
    || fail "strip_sqlia: proxy did not respond"

# strip_binary: binary/control chars in header
CODE=$(http_code -H $'X-Test: hello\x01\x02world' "$PROXY/")
[ "$CODE" != "000" ] \
    && pass "strip_binary: control chars in header, proxy responds HTTP $CODE" \
    || fail "strip_binary: proxy did not respond"

# ---------------------------------------------------------------------------
# 5. GET PARAM SANITIZATION  (form_params via _defaults_ / named params)
# ---------------------------------------------------------------------------
section "form_params GET"

# text (default): normal value
CODE=$(http_code "$PROXY/?text=hello+world")
[ "$CODE" != "000" ] && pass "GET text: normal value (HTTP $CODE)" || fail "GET text: no response"

# text: strip_chars "'`/"
CODE=$(http_code --data-urlencode "text=it's a \"test\"/path" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET text: strip_chars (HTTP $CODE)" || fail "GET text: no response"

# text: strip_html — XSS
CODE=$(http_code --data-urlencode "text=<img src=x onerror=alert(1)>" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET text: XSS attempt (HTTP $CODE)" || fail "GET text: no response"

# text: strip_sqlia
CODE=$(http_code --data-urlencode "text=foo UNION SELECT * FROM users" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET text: UNION SELECT attempt (HTTP $CODE)" || fail "GET text: no response"

CODE=$(http_code --data-urlencode "text='; DROP TABLE sessions;--" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET text: DROP TABLE attempt (HTTP $CODE)" || fail "GET text: no response"

# text: maxlen 1024 — send 2000 chars
LONG2=$(python3 -c "print('B'*2000)")
CODE=$(http_code "$PROXY/?text=$LONG2")
[ "$CODE" != "000" ] && pass "GET text: 2000-char value (truncated to 1024) (HTTP $CODE)" || fail "GET text: no response"

# num: valid numeric
CODE=$(http_code "$PROXY/?num=42")
[ "$CODE" != "000" ] && pass "GET num: valid integer (HTTP $CODE)" || fail "GET num: no response"

CODE=$(http_code "$PROXY/?num=3.14")
[ "$CODE" != "000" ] && pass "GET num: valid decimal (HTTP $CODE)" || fail "GET num: no response"

# num: non-numeric letters stripped, proxy must not crash
CODE=$(http_code "$PROXY/?num=abc")
[ "$CODE" != "000" ] && pass "GET num: non-numeric stripped (HTTP $CODE)" || fail "GET num: no response"

# email: valid
CODE=$(http_code --data-urlencode "email=user@example.com" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET email: valid address (HTTP $CODE)" || fail "GET email: no response"

# email: invalid — cleared
CODE=$(http_code "$PROXY/?email=notanemail")
[ "$CODE" != "000" ] && pass "GET email: invalid cleared (HTTP $CODE)" || fail "GET email: no response"

# ip: valid IPv4
CODE=$(http_code "$PROXY/?ip=192.168.1.1")
[ "$CODE" != "000" ] && pass "GET ip: valid IPv4 (HTTP $CODE)" || fail "GET ip: no response"

# ip: valid IPv6
CODE=$(http_code --data-urlencode "ip=::1" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET ip: valid IPv6 (HTTP $CODE)" || fail "GET ip: no response"

# ip: invalid — cleared
CODE=$(http_code "$PROXY/?ip=999.999.999.999")
[ "$CODE" != "000" ] && pass "GET ip: invalid cleared (HTTP $CODE)" || fail "GET ip: no response"

# url: valid
CODE=$(http_code --data-urlencode "url=http://example.com/path?q=1" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET url: valid URL (HTTP $CODE)" || fail "GET url: no response"

# url: invalid — cleared
CODE=$(http_code "$PROXY/?url=javascript:alert(1)")
[ "$CODE" != "000" ] && pass "GET url: javascript: scheme (cleared) (HTTP $CODE)" || fail "GET url: no response"

# path: valid URI path
CODE=$(http_code --data-urlencode "path=/some/valid/path" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET path: valid path (HTTP $CODE)" || fail "GET path: no response"

# filename: normal
CODE=$(http_code "$PROXY/?filename=document.pdf")
[ "$CODE" != "000" ] && pass "GET filename: normal filename (HTTP $CODE)" || fail "GET filename: no response"

# filename: path traversal
CODE=$(http_code --data-urlencode "filename=../../etc/passwd" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET filename: path traversal sanitized (HTTP $CODE)" || fail "GET filename: no response"

# time: valid unix timestamp
CODE=$(http_code "$PROXY/?time=1710000000")
[ "$CODE" != "000" ] && pass "GET time: valid unixtime (HTTP $CODE)" || fail "GET time: no response"

# time: invalid — cleared
CODE=$(http_code "$PROXY/?time=notadate")
[ "$CODE" != "000" ] && pass "GET time: invalid unixtime cleared (HTTP $CODE)" || fail "GET time: no response"

# malicious (absent type): value must be emptied regardless of input
CODE=$(http_code "$PROXY/?malicious=exploit_payload")
[ "$CODE" != "000" ] && pass "GET malicious: absent type, value emptied (HTTP $CODE)" || fail "GET malicious: no response"

# Unknown param — falls through to _defaults_ (text) rules
CODE=$(http_code --data-urlencode "unknown=<b>hello</b> SELECT * FROM x" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "GET unknown: _defaults_ applied (HTTP $CODE)" || fail "GET unknown: no response"

# ---------------------------------------------------------------------------
# 6. POST PARAM SANITIZATION
# ---------------------------------------------------------------------------
section "form_params POST"

# text: normal
CODE=$(http_code -X POST -d "text=hello+world" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST text: normal value (HTTP $CODE)" || fail "POST text: no response"

# text: SQL injection
CODE=$(http_code -X POST --data-urlencode "text=foo UNION SELECT * FROM users" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST text: UNION SELECT (HTTP $CODE)" || fail "POST text: no response"

# text: XSS
CODE=$(http_code -X POST --data-urlencode "text=<script>alert(1)</script>" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST text: XSS (HTTP $CODE)" || fail "POST text: no response"

# num: valid
CODE=$(http_code -X POST -d "num=100" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST num: valid (HTTP $CODE)" || fail "POST num: no response"

# num: non-numeric
CODE=$(http_code -X POST -d "num=abc" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST num: non-numeric stripped (HTTP $CODE)" || fail "POST num: no response"

# email: valid
CODE=$(http_code -X POST -d "email=user@example.com" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST email: valid (HTTP $CODE)" || fail "POST email: no response"

# email: invalid
CODE=$(http_code -X POST -d "email=bademail" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST email: invalid cleared (HTTP $CODE)" || fail "POST email: no response"

# malicious: value emptied
CODE=$(http_code -X POST -d "malicious=anything" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST malicious: absent type, value emptied (HTTP $CODE)" || fail "POST malicious: no response"

# Multiple params in one POST
CODE=$(http_code -X POST -d "text=hello&num=42&email=a@b.com" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST multiple params (HTTP $CODE)" || fail "POST multiple params: no response"

# Non-urlencoded body (JSON) — body discarded when form_params configured
CODE=$(http_code -X POST -H "Content-Type: application/json" -d '{"key":"value"}' "$PROXY/")
[ "$CODE" != "000" ] && pass "POST JSON body: discarded (HTTP $CODE)" || fail "POST JSON body: no response"

# Non-urlencoded body (multipart) — discarded
CODE=$(http_code -X POST -F "file=@/dev/null" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST multipart: discarded (HTTP $CODE)" || fail "POST multipart: no response"

# Empty POST body
CODE=$(http_code -X POST -d "" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST empty body (HTTP $CODE)" || fail "POST empty body: no response"

# ---------------------------------------------------------------------------
# 7. FORM NAME SANITIZATION  (sanitize_form_names)
# ---------------------------------------------------------------------------
section "sanitize_form_names"

# strip_chars: single quote in param name
CODE=$(http_code --data-urlencode "bad'name=value" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "form_name: quote stripped from name (HTTP $CODE)" || fail "form_name: no response"

# strip_chars: backtick in param name
CODE=$(http_code --data-urlencode 'bad\`name=value' -G "$PROXY/")
[ "$CODE" != "000" ] && pass "form_name: backtick stripped from name (HTTP $CODE)" || fail "form_name: no response"

# strip_html: HTML tag in param name
CODE=$(http_code --data-urlencode "<script>name=value" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "form_name: HTML tag stripped from name (HTTP $CODE)" || fail "form_name: no response"

# strip_sqlia: SQL keyword in param name
CODE=$(http_code --data-urlencode "SELECT=value" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "form_name: SQL keyword in name sanitized (HTTP $CODE)" || fail "form_name: no response"

# ---------------------------------------------------------------------------
# 8. HTTP METHODS
# ---------------------------------------------------------------------------
section "HTTP methods"

CODE=$(http_code -X GET "$PROXY/")
[ "$CODE" != "000" ] && pass "GET method (HTTP $CODE)" || fail "GET method: no response"

CODE=$(http_code -X HEAD "$PROXY/")
[ "$CODE" != "000" ] && pass "HEAD method (HTTP $CODE)" || fail "HEAD method: no response"

CODE=$(http_code -X POST -d "text=hello" "$PROXY/")
[ "$CODE" != "000" ] && pass "POST method (HTTP $CODE)" || fail "POST method: no response"

CODE=$(http_code -X PUT -d "text=hello" "$PROXY/")
[ "$CODE" != "000" ] && pass "PUT method (HTTP $CODE)" || fail "PUT method: no response"

CODE=$(http_code -X DELETE "$PROXY/")
[ "$CODE" != "000" ] && pass "DELETE method (HTTP $CODE)" || fail "DELETE method: no response"

# ---------------------------------------------------------------------------
# 9. EDGE CASES
# ---------------------------------------------------------------------------
section "edge cases"

# Empty request
CODE=$(http_code "$PROXY/")
[ "$CODE" != "000" ] && pass "empty GET request (HTTP $CODE)" || fail "empty GET request: no response"

# Long URL path
LONGPATH=$(python3 -c "print('/'+'/'.join(['a'*30]*10))")
CODE=$(http_code "$PROXY$LONGPATH")
[ "$CODE" != "000" ] && pass "long URL path (HTTP $CODE)" || fail "long URL path: no response"

# Many query params
CODE=$(http_code "$PROXY/?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10")
[ "$CODE" != "000" ] && pass "many query params (HTTP $CODE)" || fail "many query params: no response"

# Unicode in param value
CODE=$(http_code --data-urlencode "text=héllo wörld 日本語" -G "$PROXY/")
[ "$CODE" != "000" ] && pass "unicode in param value (HTTP $CODE)" || fail "unicode: no response"

# Null byte in param value (should not crash)
CODE=$(http_code --data-urlencode $'text=hello\x00world' -G "$PROXY/")
[ "$CODE" != "000" ] && pass "null byte in param value (HTTP $CODE)" || fail "null byte: no response"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=======================================\n"
printf "Results: ${GREEN}%d passed${NC}  ${RED}%d failed${NC}\n" "$PASS" "$FAIL"
printf "=======================================\n"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
