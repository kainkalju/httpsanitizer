# httpsanitizer

`httpsanitizer` is a `SingleHostReverseProxy` for sanitizing HTTP headers (in & out), HTTP cookies, GET/POST request parameters, and JSON/XML request bodies. Put it directly in front of a web application or web server to protect it from malicious requests.

`httpsanitizer` can run inside a Docker container as PID 1 and start the web application or web server (e.g. Apache) as a sub-process. It forwards all signals to the sub-process and will monitor and restart it if it exits or crashes.

`httpsanitizer` is a transparent drop-in solution for protecting web applications that cannot be easily modified or patched.

## Example config

The config file is in YAML format and is reloaded automatically when it changes on disk. Note that `upstream`, `server`, and `audit_log` are read only at startup and require a restart to take effect.

```yaml
---
upstream:
  url: http://127.0.0.1:8081/
  exec: "/usr/sbin/apache2 -D FOREGROUND"
server:
  addr: ":8080"
  readTimeout: 10
  writeTimeout: 10
  idleTimeout: 20
  maxHeaderBytes: 4096
  maxBodyBytes: 1048576        # 1 MB request body limit; 0 = no limit
# audit_log: true              # structured JSON audit log → stdout
# audit_log: /var/log/httpsanitizer.json
http_header_out:
  set:
    X-XSS-Protection: "1; mode=block"
    X-Content-Type-Options: "nosniff"
    X-Permitted-Cross-Domain-Policies: "none"
    Content-Security-Policy: "default-src 'self'; child-src 'none'"
  del:
    - Cache-Control
#  only:
#    - Server
#    - Date
#    - Content-Length
#    - Content-Type
#    - Cache-Control
http_cookie_in:
#  set:
#    Foo: bar
#  del:
#    - X-XSRF-TOKEN
  only:
    - PHPSESSID
http_header_in:
  set:
    User-Agent: httpsanitizer/0.1
#  del:
#    - X-XSRF-TOKEN
  only:
    - Host
    - Accept
    - Accept-Encoding
    - Accept-Language
    - User-Agent
    - Content-Length
    - Content-Type
    - Connection
    - Cookie
    - X-Forwarded-Proto
    - X-Forwarded-Host
    - X-Forwarded-For
    - X-Real-Ip
    - Referer
sanitize_http_headers:
  maxlen: 256
  strip_binary: true
  strip_html: true
  strip_sqlia: true
access_control:
  allow:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
#  deny:
#    - "203.0.113.0/24"
# block_on_detect: true
sanitize_json_body: true
sanitize_xml_body: true
sanitize_form_names:
  strip_chars: "'`/"
  strip_quotation: true
  strip_binary: true
  strip_html: true
  strip_sqlia: true
form_params:
  _defaults_:
    type: text
    maxlen: 256
    strip_chars: "'`/"
    strip_quotation: true
    strip_binary: true
    strip_html: true
    strip_sqlia: true
  text:
    type: text
    maxlen: 1024
    strip_chars: "'`/"
    strip_quotation: true
    strip_binary: true
    strip_html: true
    strip_sqlia: true
  num:
    type: numeric
  email:
    type: email
    maxlen: 200
    strip_chars: "'`/"
    strip_binary: true
  ip:
    type: ip
  url:
    type: url
    maxlen: 200
    strip_chars: "'`"
    strip_binary: true
  path:
    type: path
    maxlen: 100
    strip_chars: "'`"
    strip_binary: true
  filename:
    type: filename
    maxlen: 50
    strip_chars: "'`"
    strip_binary: true
  time:
    type: unixtime
  malicious:
    type: absent
```

Similar configuration was successfully used in Locked Shields 2021 cyber defence exercise for protecting a simple single-binary forum site inside a Docker container with no source available — exactly the case where it is more costly to fix the original site than to protect it from malicious requests.

## Docker example

### Dockerfile
```dockerfile
FROM ubuntu:bionic
RUN apt-get update && apt-get install -y \
    apache2 libapache2-mod-php7.2 php7.2-mysql php7.2-xml php7.2-bz2 php7.2-curl \
    php7.2-dom php7.2-gd php7.2-mbstring php7.2-xml php7.2-xsl php7.2-zip && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /var/www/gallery/
COPY gallery /var/www/gallery/

COPY ports.conf /etc/apache2/
COPY gallery.conf /etc/apache2/sites-available/
ADD --chown=www-data:www-data apache2 /run/apache2
ADD --chown=www-data:www-data apache2 /var/log/apache2
ADD --chown=www-data:www-data apache2 /var/lock/apache2
ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_RUN_DIR /run/apache2
ENV APACHE_LOCK_DIR /var/lock/apache2
ENV APACHE_LOG_DIR /var/log/apache2
ENV APACHE_PID_FILE /run/apache2/apache2.pid
RUN a2ensite gallery

COPY httpsanitizer /app/
COPY config.yaml /app/

CMD ["/app/httpsanitizer"]
```

Launching the container:
```
$ docker run -it --rm --name gallery gallery-image:latest
2021/04/16 22:22:01 Stated background process: /usr/sbin/apache2 -D FOREGROUND
2021/04/16 22:22:01 Starting the httpsanitizer reverse proxy server
```

Process list inside the container:
```
    1 pts/0    Ssl+   0:00 /root/httpsanitizer
   11 pts/0    S+     0:00 /usr/sbin/apache2 -D FOREGROUND
   13 pts/0    S+     0:00  \_ /usr/sbin/apache2 -D FOREGROUND
   14 pts/0    S+     0:00  \_ /usr/sbin/apache2 -D FOREGROUND
```

## Configuration reference

### upstream

`url` — host and port of the upstream web server in URL format (analogous to nginx `proxy_pass`).

`exec` — optional command line for a sub-process that `httpsanitizer` starts and monitors. The sub-process is restarted automatically if it exits.

### server

Standard `http.Server` parameters plus body size control.

| key | default | description |
|---|---|---|
| `addr` | `:8080` | Listen address |
| `readTimeout` | `10` | Read timeout in seconds |
| `writeTimeout` | `10` | Write timeout in seconds |
| `idleTimeout` | `20` | Idle (keep-alive) timeout in seconds |
| `maxHeaderBytes` | `4096` | Maximum request header size in bytes |
| `maxBodyBytes` | `0` | Maximum request body size in bytes; `0` = no limit. Oversized requests receive a 413. |

### audit_log

Enables structured JSON audit logging. Each request produces one JSON line containing the timestamp, client IP, method, host, path, response status, duration, and any sanitization events that fired. Payload values are never logged.

```yaml
audit_log: true                         # write to stdout
audit_log: /var/log/httpsanitizer.json  # write to file (appended)
```

Example audit log entry:
```json
{"ts":"2026-03-15T10:30:00.123Z","client_ip":"10.0.0.5","method":"POST","host":"example.com","path":"/login","status":200,"duration_ms":12,"events":[{"rule":"form_params","field":"username","location":"post"},{"rule":"sanitize_http_headers","field":"X-Custom","location":"header"}]}
```

When `block_on_detect` is enabled, blocked requests include `"blocked":true`. IP-denied requests include `"denied":true`.

### access_control

IP-based allowlist and blocklist. Accepts bare IP addresses and CIDR ranges. The deny list is evaluated first; a request that is not denied must then match the allow list (if configured) to proceed.

```yaml
access_control:
  allow:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
    - "203.0.113.5"
  deny:
    - "10.99.0.0/24"
```

| scenario | behaviour |
|---|---|
| only `allow` configured | non-matching IPs receive 403 |
| only `deny` configured | matching IPs receive 403; all others pass |
| both configured | deny checked first, then allow |
| neither configured | all IPs pass |

Source IP is always taken from the direct TCP connection (`RemoteAddr`), not from `X-Forwarded-For`, which clients can forge.

### block_on_detect

When set to `true`, any request where a sanitizer modifies a value is blocked with a 403 response and the upstream never receives it. The default behaviour (sanitize and forward) is used when this key is absent.

```yaml
block_on_detect: true
```

### http_header_out

Filters applied to response headers before they are sent to the client.

`set` — headers to add or override in the response.

`del` — header names to remove from the response.

`only` — whitelist; only listed headers are forwarded to the client. Applied before `set`, so proxy-injected headers are never affected by the whitelist.

### http_header_in

Filters applied to incoming request headers before forwarding to upstream.

`set` — headers to add or override (e.g. force a specific `User-Agent`).

`del` — header names to remove.

`only` — whitelist; only listed headers are forwarded to upstream.

### http_cookie_in

Filters applied to incoming cookies before forwarding to upstream.

`set` — cookies to add or override.

`del` — cookie names to remove.

`only` — whitelist; only listed cookies are forwarded to upstream.

### sanitize_http_headers

Applies content filters to all incoming request header values.

| key | description |
|---|---|
| `maxlen` | Truncate header values longer than this |
| `strip_chars` | Remove specific characters |
| `strip_quotation` | Remove double-quote characters |
| `strip_binary` | Strip control/binary characters (NUL, BEL, TAB, etc.) |
| `strip_html` | Remove HTML tags |
| `strip_sqlia` | Mask SQL keywords (SELECT, INSERT, DROP, …) with `xxxxxx` |

### sanitize_json_body

When set to `true`, parses `application/json` request bodies and applies `form_params` rules to every string value. Object field names are used as the `form_params` lookup key; `_defaults_` applies to any field not explicitly listed. Non-string values (numbers, booleans, null) pass through unchanged.

```yaml
sanitize_json_body: true
```

### sanitize_xml_body

When set to `true`, parses `text/xml` and `application/xml` request bodies and applies `form_params` rules to all character data and attribute values. The enclosing element name is used as the `form_params` lookup key.

```yaml
sanitize_xml_body: true
```

### sanitize_form_names

Applies content filters to incoming request parameter *names* (not values). Same filter keys as `sanitize_http_headers`.

### form_params

Applies type validation and content filters to GET query parameters and POST form body values. For JSON and XML bodies, field names are matched against these rules when `sanitize_json_body` or `sanitize_xml_body` is enabled.

The top-level key is the parameter name (e.g. `email`, `num`). The special key `_defaults_` applies to any parameter not explicitly listed.

#### type

| type | behaviour |
|---|---|
| `text` | String with configurable filters (see filter keys below) |
| `numeric` | Allows only digits, `.` and `,`; everything else is stripped |
| `email` | Validates as a properly formatted e-mail address; invalid → empty string |
| `ip` | Validates as IPv4 or IPv6 address; invalid → empty string |
| `url` | Validates as a full URL; invalid → empty string |
| `path` | Validates as a URI path; invalid → empty string |
| `filename` | Strips path traversal sequences (`../../`); sanitises to a safe filename |
| `unixtime` | Validates as a Unix timestamp integer; invalid → empty string |
| `absent` | Parameter is always removed from the forwarded request |

#### filter keys (for `text` type)

| key | description |
|---|---|
| `maxlen` | Truncate values longer than this number of bytes |
| `strip_chars` | Remove the listed characters from values |
| `strip_quotation` | Remove double-quote characters |
| `strip_binary` | Strip control/binary characters |
| `strip_html` | Remove HTML tags |
| `strip_sqlia` | Mask SQL keywords with `xxxxxx` |

## Author

Kain Kalju

## License

MIT Licensed. See the [LICENSE](LICENSE) file for details.
