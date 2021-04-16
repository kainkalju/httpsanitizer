# httpsanitizer

`httpsanitizer` is `SingleHostReverseProxy` for sanitizing HTTP header (in & out), HTTP Cookies and GET / POST request parameters. You can put it directly front of web application /webserver what you need to protect from malicious requests.

`httpsanitizer` can run inside Docker container as process 1 and it can start web application or webserver (apache) as sub-process. It will pass all singals to sub-process also and will monitor and restart if sub-process exits (in case of crashing).

`httpsanitizer` will be transparent drop-in solution for protecting web applications that you cannot fix easily.

## Example config

Config file is in YAML format and will be reloaded once it changes but unfortunately not all the parems could be changed runtime.

```
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
http_header_out:
  set:
    X-XSS_Protection: "1; mode=block"
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
#  maxlen: 256
#  strip_quotation: true
  strip_binary: true
  strip_html: true
  strip_sqlia: true
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

Similar configuration was successfully used in Locked Shields 2021 cyber defence exercise for protecting simple single-binary forum site inside the Docker container with no source available. This is exactly the case where it's more costly to fix the original site than trying to protect it from malicious requests.

## Configuration params

### upstream

`url` defines host+port number of upstream web server in URL format - think proxy_pass and nginx

`exec` is optonal param for defining command line for sub-process what `httpsanitizer` needs to start and monitor

### server

params for [http.Server](https://golang.org/pkg/net/http/#Server)

```
server := &http.Server{
	Addr:           serverAddr,
	Handler:        router,
	ReadTimeout:    serverReadTimeout * time.Second,
	WriteTimeout:   serverWriteTimeout * time.Second,
	IdleTimeout:    serverIdleTimeout * time.Second,
	MaxHeaderBytes: serverMaxHeaderBytes,
}
```

### http_header_out

params for filtering outgoing HTTP headers

`set` will define new HTTP headers to add to request

`del` will define HTTP header names what we should remove

`only` is whitelist for HTTP headers what we will pass through. Will also apply to params that have `set`

### http_cookie_in

params for filtering incoming HTTP Cookie

`set` will define new Cookies to add to request

`del` will define Cookie names what we should remove

`only` is whitelist for Cookies what we will pass through. Will also apply to params that have `set`

### http_header_in

params for filtering incoming HTTP headers

`set` will define new HTTP headers to add to request

`del` will define HTTP header names what we should remove

`only` is whitelist for HTTP headers what we will pass through. Will also apply to params that have `set`

### sanitize_http_headers

applies filters to incoming HTTP header values. Similar validator filtering than we are doing for request params

### sanitize_form_names

applies filters to incoming request param names. Similar validator filtering than we are doing for request params (values)

### form_params

applies filters to GET and/or POST request params (values)

first level key is the param name like `text`, `num`, `malicious`, etc. in the example below. And optional `_default_` applies to those form params where we haven't defined explicitly.

`type` defines param type. Possible values are `text`, `numeric`, `email`, `ip`, `url`, `path`, `filename`, `unixtime` and `absent`

`absent` is special type which basically means remove it.

All other types are probably self explanatory. `text` will allow **strings** and `numeric` will allow only 0-9 and .,

`email` is trying to validate properly formatted e-mail address and `ip` will validate ipv4 & ipv6 addresses. `filename` will strip down typical ../../../../ path attack.

#### filter names

`strip_chars` allows to define specific characters that will be striped from the param value.

`strip_quotation` will remove double quotation marks

`strip_binary` will strip all character names outside of defined 8-bit letters like TAB, NUL, BEL, etc.

`strip_html` will remove HTML tags from text

`strip_sqlia` will try to mask SQL injection attempt with ***** marks to it cannot properly execute even attempt succeed to break SQL query into several queries in the web application

## Author

Kain Kalju

## License

MIT Licensed. See the LICENSE file for details.
