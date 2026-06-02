package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mattaustin/redir/internal/api"
	dnsserver "github.com/mattaustin/redir/internal/dns"
	"github.com/mattaustin/redir/internal/proxy"
	"github.com/mattaustin/redir/internal/redirect"
	"github.com/mattaustin/redir/internal/store"
)

//go:embed ui
var uiFS embed.FS

func main() {
	port := flag.Int("port", 8080, "HTTP port for UI, API, and redirects")
	dnsPort := flag.Int("dns-port", 5300, "UDP port for DNS server (use 53 with root)")
	domain := flag.String("domain", "redir.local", "Base domain for DNS rebind hostnames")
	dbPath := flag.String("db", defaultDBPath(), "Path to SQLite database file")
	publicIP := flag.String("public-ip", "", "Public IP for rebind first-hop (auto-detected if empty)")
	bindAddr := flag.String("bind", "0.0.0.0", "Bind address")
	flag.Parse()

	// auto-detect public IP if not set
	if *publicIP == "" {
		*publicIP = detectPublicIP()
	}

	// ensure db directory exists
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
		log.Fatalf("create db dir: %v", err)
	}

	s, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer s.Close()

	cfg := api.Config{
		HTTPPort: *port,
		DNSPort:  *dnsPort,
		Domain:   *domain,
		PublicIP: *publicIP,
		BindAddr: *bindAddr,
		IptablesCmd: fmt.Sprintf(
			"sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port %d\n"+
				"sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port %d",
			*dnsPort, *dnsPort),
		PfCmd: fmt.Sprintf(
			`echo "rdr pass on lo0 proto udp from any to any port 53 -> 127.0.0.1 port %d" | sudo pfctl -ef -`,
			*dnsPort),
	}

	mux := http.NewServeMux()

	// static UI
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(sub))))

	// root → UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/index.html", http.StatusFound)
	})

	// redirect engine
	rh := redirect.New(s)
	mux.Handle("/r/", rh)

	// proxy
	mux.HandleFunc("/proxy", proxy.Handler)

	// api
	apiHandler := api.New(s, cfg)
	apiHandler.Register(mux)

	httpSrv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", *bindAddr, *port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	dnsSrv := dnsserver.New(s, *domain, *dnsPort)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	printBanner(*port, *dnsPort, *domain, *publicIP, cfg.PfCmd, cfg.IptablesCmd)

	// start DNS server
	go func() {
		log.Printf("[dns] listening on UDP %s:%d", *bindAddr, *dnsPort)
		if err := dnsSrv.Start(); err != nil {
			log.Printf("[dns] stopped: %v", err)
		}
	}()

	// start HTTP server
	go func() {
		log.Printf("[http] listening on %s:%d", *bindAddr, *port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[http] fatal: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutCtx)
	dnsSrv.Shutdown(shutCtx)
}

func defaultDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".redir", "redir.db")
}

func detectPublicIP() string {
	// try outbound connection to determine local IP (no packets sent)
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String()
}

func printBanner(httpPort, dnsPort int, domain, publicIP, pfCmd, iptablesCmd string) {
	fmt.Printf(`
┌─────────────────────────────────────────────────────┐
│  redir — redirect security testing tool             │
└─────────────────────────────────────────────────────┘

  Web UI:     http://localhost:%d
  Redirects:  http://localhost:%d/r/<label-or-id>
  DNS server: UDP 0.0.0.0:%d  (domain: %s)
  Public IP:  %s

  To redirect system port 53 → %d (macOS):
    %s

  To redirect system port 53 → %d (Linux):
    %s

`, httpPort, httpPort, dnsPort, domain, publicIP, dnsPort, pfCmd, dnsPort, iptablesCmd)
}
