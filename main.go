package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/api/idtoken"
)

var (
	domainConfigJSON = flag.String("domainConfig", "", "Configuration for the oauth domain this is running on as JSON")
	routingConfig    = flag.String("routingConfig", "", "Configuration for routing requests. Comma seperated list of <path> -> <backend url>. Eg: /index -> http://localhost:8090/path")
)

func init() {
	// Disable log prefixes such as the default timestamp.
	// Prefix text prevents the message from being parsed as JSON.
	// A timestamp is added when shipping logs to Cloud Logging.
	log.SetFlags(0)
}

type entry struct {
	Message  string            `json:"message"`
	Severity string            `json:"severity,omitempty"`
	Labels   map[string]string `json:"logging.googleapis.com/labels,omitempty"`
	Trace    string            `json:"logging.googleapis.com/trace,omitempty"`
}

func (e entry) String() string {
	if e.Severity == "" {
		e.Severity = "INFO"
	}
	if e.Labels == nil {
		e.Labels = make(map[string]string)
	}
	e.Labels["pid"] = string(os.Getpid())
	e.Labels["name"] = string("auth-server")
	out, err := json.Marshal(e)
	if err != nil {
		log.Printf("json.Marshal: %v", err)
	}
	return string(out)
}

func logInfo(message string) {
	log.Println(entry{Message: message})
}

func logFatal(message string) {
	log.Fatal(entry{Message: message, Severity: "CRITICAL"})
}

func logReq(r *http.Request, message string) {
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID != "" {
		traceHeader := r.Header.Get("X-Cloud-Trace-Context")
		traceParts := strings.Split(traceHeader, "/")
		if len(traceParts) > 0 && len(traceParts[0]) > 0 {
			trace := fmt.Sprintf("projects/%s/traces/%s", projectID, traceParts[0])
			log.Println(entry{Message: message, Trace: trace})
			return
		}
	}
	logInfo(message)
}

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

type domainConfig struct {
	ClientID     string
	LoginURL     string
	CookieName   string
	CookieDomain string
	AllowedUsers []string
}

func (c *domainConfig) requireAuth(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r := c.LoginURL + req.URL.String()

		token, err := req.Cookie(c.CookieName)
		if err != nil {
			http.Redirect(w, req, r, http.StatusFound)
			return
		}

		payload, err := idtoken.Validate(req.Context(), token.Value, c.ClientID)
		if err != nil {
			http.Redirect(w, req, r, http.StatusFound)
			return
		}

		// https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token
		iss := payload.Claims["iss"]
		if iss != "accounts.google.com" && iss != "https://accounts.google.com" {
			http.Redirect(w, req, r, http.StatusFound)
			return
		}

		user := payload.Claims["email"]
		for _, u := range c.AllowedUsers {
			if u == user {
				logReq(req, "Auth: Request authorized, forwarding to backend.")
				h.ServeHTTP(w, req)
				logReq(req, "Auth: Got response. All done.")
				return
			}
		}
		http.Error(w, fmt.Sprintf("%s does not have permission to view this page.", user), http.StatusForbidden)
	})
}

func (c *domainConfig) login(w http.ResponseWriter, req *http.Request) {
	// Parse out the final destination if one is set in the "target" query param.
	err := req.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	target := req.FormValue("target")

	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	payload := func() string {
		cookie, err := req.Cookie(c.CookieName)
		if err != nil {
			return fmt.Sprintf("No cookie with name '%s' found.", c.CookieName)
		}
		payload, err := idtoken.Validate(req.Context(), cookie.Value, c.ClientID)
		if err != nil {
			return fmt.Sprint(err)
		}
		return fmt.Sprintf("%+v", payload)
	}()

	// From https://developers.google.com/identity/sign-in/web/sign-in
	const tmpl = `<!DOCTYPE html>
    <html>
      <head>
        <meta name="google-signin-client_id" content="{{.ClientID}}">
        <script src="https://apis.google.com/js/platform.js" async defer></script>
        <script>
          function onSignIn(googleUser) {
            var profile = googleUser.getBasicProfile();
            const authResponse = googleUser.getAuthResponse(true);
            document.getElementById('loginData').innerText = ` + "`" + `
AccessToken: ${authResponse.access_token}
IDToken: ${authResponse.id_token}
ID:   ${profile.getId()}
Name: ${profile.getName()}
Image URL: ${profile.getImageUrl()}
Email: ${profile.getEmail()}
            ` + "`" + `;
            document.cookie = '{{.CookieName}}=' + authResponse.id_token + '; Domain={{.CookieDomain}}; Secure; SameSite=Strict';
            if ('{{.Target}}') window.location = '{{.Target}}';
          }
        </script>
      </head>
      <body>
        <div class="g-signin2" data-onsuccess="onSignIn"></div>
        <div>
          <h3>Login Data Debug</h3>
          <pre id="loginData"></pre>
        </div>
        <div>
          <h3>HTTP Request Debug</h3>
          <pre>{{.ReqDump}}</pre>
        </div>
	<div>
	  <h3>Payload debug</h3>
	  <pre>{{.Payload}}</pre>
	</div>
      </body>
    </html>`

	t, err := template.New("login").Parse(tmpl)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	t.Execute(w, map[string]interface{}{
		"ClientID":     c.ClientID,
		"LoginURL":     c.LoginURL,
		"CookieName":   c.CookieName,
		"CookieDomain": c.CookieDomain,
		"Target":       target,
		"ReqDump":      string(reqDump),
		"Payload":      payload,
	})
}

func main() {
	flag.Parse()
	var err error

	// https://cloud.google.com/run/docs/reference/container-contract#port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}
	logInfo(fmt.Sprintf("Serving on %s.", port))

	if *domainConfigJSON == "" {
		logFatal("-domainConfig is empty, exiting.")
	}
	var dc domainConfig
	err = json.Unmarshal([]byte(*domainConfigJSON), &dc)
	if err != nil {
		logFatal(err.Error())
	}
	logInfo(fmt.Sprintf("Domain configuration: %+v", dc))

	rc, err := parseRoutingConfig(*routingConfig)
	if err != nil {
		logFatal(err.Error())
	}
	logInfo(fmt.Sprintf("Routing configuration: %q", rc))

	// Maybe create exporter.
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID != "" {
		ctx := context.Background()
		exporter, err := texporter.New(texporter.WithProjectID(projectID))
		if err != nil {
			logFatal(fmt.Sprintf("texporter.NewExporter: %v", err))
		}
		tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter))
		defer tp.ForceFlush(ctx) // flushes any pending spans
		otel.SetTracerProvider(tp)
		logInfo("Tracing has been configured.")
	}

	for _, r := range rc {
		rp := httputil.NewSingleHostReverseProxy(r.Backend)
		// This is the default transport but with tracing and the timeout dropped from 30 seconds to 3.
		rp.Transport = otelhttp.NewTransport(&http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 3 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		})

		// Before moving on, lets establish a connection to the backend.
		client := &http.Client{Transport: rp.Transport}
		if _, err = client.Get(r.Backend.String()); err != nil {
			logFatal(fmt.Sprintf("Unable to connect to a backend: %v", err))
		}

		h := otelhttp.NewHandler(rp, "ReverseProxyHandler")
		h = http.StripPrefix(r.Path, h)
		h = dc.requireAuth(h)
		http.Handle(r.Path, h)
	}
	http.HandleFunc("/login", dc.login)
	logFatal(http.ListenAndServe(":"+port, nil).Error())
}
