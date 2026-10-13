// A minimal forward proxy built on github.com/elazarl/goproxy, the most widely used Go forward
// proxy library, for the load-testing comparison (docs/project/performance.md). It is configured
// the way the harness configures MicroProxy and LittleProxy: a plain HTTP forward proxy on a
// loopback port (absolute-form requests, and CONNECT), no access log, no caching, the same idle and
// upstream connect timeouts, and header limits close to MicroProxy's. GOMAXPROCS is left at Go's
// default, which follows the CPUs the process is pinned to.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/elazarl/goproxy"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	idle := flag.Duration("idle-timeout", 70*time.Second, "idle connection timeout, client and upstream side")
	connect := flag.Duration("connect-timeout", 40*time.Second, "upstream connect timeout")
	version := flag.Bool("version", false, "print the goproxy and Go versions and exit")
	flag.Parse()
	if *version {
		printVersion()
		return
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	// No access log; goproxy's warnings are dropped too (the other proxies log errors only).
	proxy.Logger = log.New(io.Discard, "", 0)
	proxy.Tr = &http.Transport{
		// Never chain through a proxy from the environment.
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: *connect, KeepAlive: 30 * time.Second}).DialContext,
		// Go's default keeps only 2 idle upstream connections per host, which would close and reopen
		// connections under any concurrency; keep enough for every client connection instead.
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   65536,
		IdleConnTimeout:       *idle,
		ResponseHeaderTimeout: *idle,
		// Forward bodies untouched (Go would otherwise ask for gzip and decompress).
		DisableCompression: true,
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           proxy,
		IdleTimeout:       *idle,
		ReadHeaderTimeout: *idle,
		MaxHeaderBytes:    8192 + 16384,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.WriteString("goproxy listening on " + ln.Addr().String() + "\n")
	log.Fatal(server.Serve(ln))
}

// printVersion prints the goproxy module version this binary was built with, and the Go version.
func printVersion() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		os.Stdout.WriteString("unknown\n")
		return
	}
	goproxyVersion := "unknown"
	for _, dep := range info.Deps {
		if dep.Path == "github.com/elazarl/goproxy" {
			goproxyVersion = dep.Version
		}
	}
	os.Stdout.WriteString("github.com/elazarl/goproxy " + goproxyVersion + " (" + info.GoVersion + ")\n")
}
