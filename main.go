package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"google.golang.org/api/idtoken"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
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
				h.ServeHTTP(w, req)
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
	const tmpl = `
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
	log.Printf("Serving on %s.\n", port)

	if *domainConfigJSON == "" {
		log.Fatal("-domainConfig is empty, exiting.")
	}
	var dc domainConfig
	err = json.Unmarshal([]byte(*domainConfigJSON), &dc)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Domain configuration: %+v\n", dc)

	rc, err := parseRoutingConfig(*routingConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Routing configuration: %q\n", rc)

	for _, r := range rc {
		http.HandleFunc(r.Path, dc.requireAuth(http.StripPrefix(r.Path, httputil.NewSingleHostReverseProxy(r.Backend))))
	}
	http.HandleFunc("/login", dc.login)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
