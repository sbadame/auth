package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/crypto/acme/autocert"

	"github.com/sbadame/auth/internal/auth"
	"github.com/sbadame/auth/internal/logging"
	"github.com/sbadame/auth/internal/reverseproxy"
)

var (
	domainConfigJSON = flag.String("domainConfig", "", "Configuration for the oauth domain this is running on as JSON")
	routingConfig    = flag.String("routingConfig", "", "Configuration for routing requests. Comma seperated list of <path> -> <backend url>. Eg: /index -> http://localhost:8090/path")
)

type route struct {
	Path    string
	Backend *url.URL
}

func parseRoutingConfig(c string) ([]route, error) {
	routes := make([]route, 0)
	for _, r := range strings.Split(c, ",") {
		pathAndURL := strings.SplitN(r, "->", 2)
		u, err := url.Parse(strings.TrimSpace(pathAndURL[1]))
		if err != nil {
			return nil, err
		}
		routes = append(routes, route{strings.TrimSpace(pathAndURL[0]), u})
	}
	return routes, nil
}

func main() {
	logger := log.Default()

	if projectID := os.Getenv("GOOGLE_CLOUD_PROJECT"); projectID == "" {
		// Not running in a cloud, lets add file names
		logger.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		// Disable log prefixes such as the default timestamp.
		// Prefix text prevents the message from being parsed as JSON.
		// A timestamp is added when shipping logs to Cloud Logging.
		log.SetFlags(0)
		logger.SetFlags(0)

		// Attach the open tracing stuff
		ctx := context.Background()
		exporter, err := texporter.New(texporter.WithProjectID(projectID))
		if err != nil {
			logger.Fatalf("texporter.NewExporter: %v", err)
		}
		tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter))
		defer tp.ForceFlush(ctx) // flushes any pending spans
		otel.SetTracerProvider(tp)
		logger.Println("Tracing has been configured.")
	}

	flag.Parse()
	http.HandleFunc("/flags", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><pre>%s</pre></body></html>", strings.Join(os.Args, "\n"))
	}))

	var err error

	// https://cloud.google.com/run/docs/reference/container-contract#port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}

	// Have an easy to access path for ensuring that this code is even running.
	// /healthz is a reserved URL on Cloud Run: https://cloud.google.com/run/docs/issues#ah
	http.HandleFunc("/health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))

	http.HandleFunc("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Welcome to the auth server.")
	}))

	// If we're configured to run behind a domain, set that up
	var domainConfig auth.DomainConfig
	if *domainConfigJSON == "" {
		logger.Println("-domainConfig is empty. Running with no auth.")
	} else if err = json.Unmarshal([]byte(*domainConfigJSON), &domainConfig); err != nil {
		logger.Fatal(err.Error())
	}
	logger.Printf("Domain configuration: %+v", &domainConfig)
	http.HandleFunc("/login", domainConfig.RequireAuth(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "You're logged in.")
	})))

	// Setup the routing config.
	routingConfig, err := parseRoutingConfig(*routingConfig)
	if err != nil {
		logger.Fatal(err.Error())
	}
	logger.Printf("Routing configuration: %q", routingConfig)

	transport := otelhttp.NewTransport(&http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 3 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	})

	client := &http.Client{Transport: transport}

	for _, r := range routingConfig {
		reverseProxy := &reverseproxy.ReverseProxy{
			Backend: r.Backend,
			Client:  client,
			Logger:  logger,
		}

		if err := reverseProxy.HealthCheck(); err != nil {
			logger.Fatalf(err.Error())
		}

		h := logging.Handler(log.New(log.Writer(), "ReverseProxyHandler - ", log.Flags()), otelhttp.NewHandler(reverseProxy, "ReverseProxyHandler"))
		h = logging.Handler(log.New(log.Writer(), "StripPrefixHandler - ", log.Flags()), http.StripPrefix(r.Path, h))
		if domainConfig.ClientID != "" {
			l := log.New(log.Writer(), "AuthHandler - ", log.Flags())
			h = logging.Handler(l, domainConfig.RequireAuth(l, h))
		}
		http.Handle(r.Path, h)
		logger.Printf("Registered %s --> %s", r.Path, r.Backend)
	}

	if domainConfig.HostName == "" {
		// Only serving HTTP
		logger.Printf("Serving HTTP on %s.\n", port)
		logger.Fatalln(http.ListenAndServe(":"+port, nil).Error())
	} else {

		// Serve SSL on the HTTP port + 1.
		sslPort := 0
		if sslPort, err = strconv.Atoi(port); err != nil {
			log.Fatal(err.Error())
		}
		sslPort += 1

		logger.Printf("Serving HTTPS on %d with HTTP redirect on %s", sslPort, port)

		// Setup an HTTP server on $PORT that redirects to the HTTPS server.
		s := http.Server{
			Addr:    ":" + port,
			Handler: http.RedirectHandler("https://"+domainConfig.HostName, http.StatusMovedPermanently),
		}
		go func() { log.Fatal(s.ListenAndServe()) }()

		// Setup the actual HTTPS server on $PORT + 1
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(domainConfig.CertificateDirectory),
			HostPolicy: autocert.HostWhitelist(domainConfig.HostName),
		}

		ss := &http.Server{
			Addr:      ":" + strconv.Itoa(sslPort),
			TLSConfig: m.TLSConfig(),
		}
		log.Fatal(ss.ListenAndServeTLS("", ""))
	}
}
