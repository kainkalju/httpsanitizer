package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

// Global koanf instance. Use "." as the key path delimiter. This can be "/" or any character.
var k = koanf.New(".")

func main() {
	var execCmd string = ""
	var upstreamURL = "http://127.0.0.1:9000/"
	var serverAddr string = ":8080"
	var serverReadTimeout time.Duration = 10
	var serverWriteTimeout time.Duration = 10
	var serverIdleTimeout time.Duration = 20
	var serverMaxHeaderBytes int = 4096

	// Load YAML config.
	cfg := file.Provider("config.yaml")
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
	if k.Exists("server.addr") {
		serverReadTimeout = time.Duration(k.Int("server.readTimeout"))
	}
	if k.Exists("server.addr") {
		serverWriteTimeout = time.Duration(k.Int("server.writeTimeout"))
	}
	if k.Exists("server.addr") {
		serverIdleTimeout = time.Duration(k.Int("server.idleTimeout"))
	}
	if k.Exists("server.addr") {
		serverMaxHeaderBytes = k.Int("server.maxHeaderBytes")
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
				// try to start again
				cmd = execProgram(execCmd)
			}
		}()
	}

	router := httprouter.New()
	origin, _ := url.Parse(upstreamURL)
	path := "/*catchall"

	reverseProxy := httputil.NewSingleHostReverseProxy(origin)

	reverseProxy.Director = func(req *http.Request) {

		if req.Method == "POST" {
			sanitizingPOST(req, k)
		}

		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", origin.Host)
		sanitizingIncomingHeaders(req, k)
		req.URL.Scheme = origin.Scheme
		req.URL.Host = origin.Host
		//req.URL.RawQuery = "foo=bar&1=2" // get query_string

		data := url.Values{}
		req.ParseForm()
		for k, vv := range req.PostForm {
			for _, v := range vv {
				if k == "test" {
					v = "censored"
				}
				data.Set(k, v)
			}
		}
		newBody := data.Encode()
		req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(newBody)))
		req.ContentLength = int64(len(newBody))
	}

	router.Handle("HEAD", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		startTime := time.Now()
		reverseProxy.ServeHTTP(w, r)
		log.Printf("from: %s %s %s%s duration: %s\n", r.RemoteAddr, r.Method, r.Host, r.RequestURI, time.Since(startTime))
	})
	router.Handle("GET", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		startTime := time.Now()
		reverseProxy.ServeHTTP(w, r)
		log.Printf("from: %s %s %s%s duration: %s\n", r.RemoteAddr, r.Method, r.Host, r.RequestURI, time.Since(startTime))
	})
	router.Handle("POST", path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		startTime := time.Now()
		reverseProxy.ServeHTTP(w, r)
		log.Printf("from: %s %s %s%s duration: %s\n", r.RemoteAddr, r.Method, r.Host, r.RequestURI, time.Since(startTime))
	})

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

func sanitizingIncomingHeaders(req *http.Request, k *koanf.Koanf) {

	if k.Exists("http_header_in.set") {
		for _, name := range k.MapKeys("http_header_in.set") {
			value := k.String("http_header_in.set." + name)
			req.Header.Set(name, value)
			log.Println("set header: ", name, value)
		}
	}
	if k.Exists("http_header_in.del") {
		for _, name := range k.MapKeys("http_header_in.del") {
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

}

func sanitizingPOST(req *http.Request, k *koanf.Koanf) {
}
