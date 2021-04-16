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

## Docker example

### Dockerfile
```
FROM ubuntu:bionic
RUN apt-get update && apt-get install -y \
    apache2 libapache2-mod-php7.2 php7.2-mysql php7.2-xml php7.2-bz2 php7.2-curl \
    php7.2-dom php7.2-gd php7.2-mbstring php7.2-xml php7.2-xsl php7.2-zip \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /var/www/gallery/
COPY gallery /var/www/gallery/

COPY ports.conf /etc/apache2/
COPY gallery.conf etc/apache2/sites-available/
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

launching container:
```
$ docker run -it --rm --name gallery gallery-image:latest
2021/04/16 22:22:01 Stated background process: /usr/sbin/apache2 -D FOREGROUND
2021/04/16 22:22:01 Starting the httpsanitizer reverse proxy server
```

and inside the container process list will look like:
```
    1 pts/0    Ssl+   0:00 /root/httpsanitizer
   11 pts/0    S+     0:00 /usr/sbin/apache2 -D FOREGROUND
   13 pts/0    S+     0:00  \_ /usr/sbin/apache2 -D FOREGROUND
   14 pts/0    S+     0:00  \_ /usr/sbin/apache2 -D FOREGROUND
   15 pts/0    S+     0:00  \_ /usr/sbin/apache2 -D FOREGROUND
   16 pts/0    S+     0:00  \_ /usr/sbin/apache2 -D FOREGROUND
   17 pts/0    S+     0:00  \_ /usr/sbin/apache2 -D FOREGROUND
```

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

`strip_binary` will strip all characters outside of defined 8-bit letters like TAB, NUL, BEL, etc.

`strip_html` will remove HTML tags from text

`strip_sqlia` will try to mask SQL injection attempt with ***** marks so it cannot properly execute even attempt succeed to break SQL query into several queries in the web application

## Author

Kain Kalju

## License

MIT Licensed. See the LICENSE file for details.
