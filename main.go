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
	"syscall"
	"time"

	"github.com/mattaustin/redir/internal/api"
	"github.com/mattaustin/redir/internal/auth"
	appcfg "github.com/mattaustin/redir/internal/config"
	dnsserver "github.com/mattaustin/redir/internal/dns"
	"github.com/mattaustin/redir/internal/proxy"
	"github.com/mattaustin/redir/internal/redirect"
	"github.com/mattaustin/redir/internal/store"
)

//go:embed ui
var uiFS embed.FS

func main() {
	// Flags mirror config file fields so CLI can override any setting.
	configPath := flag.String("config", appcfg.DefaultPath(), "Path to config file")
	port := flag.Int("port", 0, "HTTP port (overrides config)")
	dnsPort := flag.Int("dns-port", 0, "DNS UDP port (overrides config)")
	domain := flag.String("domain", "", "Rebind base domain (overrides config)")
	dbPath := flag.String("db", "", "SQLite database path (overrides config)")
	publicIP := flag.String("public-ip", "", "Public IP for rebind first-hop (overrides config)")
	bindAddr := flag.String("bind", "", "Bind address (overrides config)")
	flag.Parse()

	cfg, err := appcfg.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// CLI flags override config file — only apply flags that were explicitly set.
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "port":
			cfg.Port = *port
		case "dns-port":
			cfg.DNSPort = *dnsPort
		case "domain":
			cfg.Domain = *domain
		case "db":
			cfg.DB = *dbPath
		case "public-ip":
			cfg.PublicIP = *publicIP
		case "bind":
			cfg.Bind = *bindAddr
		}
	})

	if cfg.PublicIP == "" {
		cfg.PublicIP = detectPublicIP()
	}

	if err := os.MkdirAll(dirOf(cfg.DB), 0700); err != nil {
		log.Fatalf("create db dir: %v", err)
	}

	s, err := store.Open(cfg.DB)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer s.Close()

	iptablesCmd := fmt.Sprintf(
		"sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port %d\n"+
			"sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port %d",
		cfg.DNSPort, cfg.DNSPort)
	pfCmd := fmt.Sprintf(
		`echo "rdr pass on lo0 proto udp from any to any port 53 -> 127.0.0.1 port %d" | sudo pfctl -ef -`,
		cfg.DNSPort)

	apiCfg := api.Config{
		HTTPPort:    cfg.Port,
		DNSPort:     cfg.DNSPort,
		Domain:      cfg.Domain,
		PublicIP:    cfg.PublicIP,
		BindAddr:    cfg.Bind,
		IptablesCmd: iptablesCmd,
		PfCmd:       pfCmd,
	}

	mux := http.NewServeMux()

	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(sub))))

	indexHTML, _ := fs.ReadFile(uiFS, "ui/index.html")
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})

	rh := redirect.New(s)
	mux.Handle("/r/", rh)

	mux.HandleFunc("/proxy", proxy.Handler)

	protect := auth.Middleware(s)
	mux.HandleFunc("/api/auth/register", auth.RegisterHandler(s))
	mux.HandleFunc("/api/auth/login", auth.LoginHandler(s))
	mux.HandleFunc("/api/auth/logout", auth.LogoutHandler(s))
	mux.Handle("/api/auth/me", protect(auth.MeHandler(s, cfg.AdminEmails)))

	apiHandler := api.New(s, apiCfg, cfg.AdminEmails)
	apiHandler.Register(mux, protect)

	httpSrv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Bind, cfg.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	dnsSrv := dnsserver.New(s, cfg.Domain, cfg.DNSPort)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	printBanner(cfg.Port, cfg.DNSPort, cfg.Domain, cfg.PublicIP, pfCmd, iptablesCmd)

	go func() {
		log.Printf("[dns] listening on UDP %s:%d", cfg.Bind, cfg.DNSPort)
		if err := dnsSrv.Start(); err != nil {
			log.Printf("[dns] stopped: %v", err)
		}
	}()

	go func() {
		log.Printf("[http] listening on %s:%d", cfg.Bind, cfg.Port)
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

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}

func detectPublicIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
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
