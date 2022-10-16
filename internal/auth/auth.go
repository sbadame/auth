package auth

import (
	"fmt"
	"github.com/sbadame/auth/internal/logging"
	"google.golang.org/api/idtoken"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
)

type DomainConfig struct {
	ClientID     string
	LoginURL     string
	CookieName   string
	CookieDomain string
	AllowedUsers []string

	// When populated the server will serve SSL on $PORT+1.
	// The server will use autocert to get a certificate for HostName.
	// $PORT will serve HTTP but redirect all requests to the SSL port.
	HostName string

	// Where to store the certificates fetched by auto-cert.
	CertificateDirectory string
}

func (c *DomainConfig) RequireAuth(logger *log.Logger, h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token, err := req.Cookie(c.CookieName)
		if err != nil {
			w.Header().Add("X-sandrio-auth-message", fmt.Sprintf("Missing cookie: %s", c.CookieName))
			c.login(w, req)
			return
		}

		payload, err := idtoken.Validate(req.Context(), token.Value, c.ClientID)
		if err != nil {
			w.Header().Add("X-sandrio-auth-message", fmt.Sprintf("Invalid cookie: %v", err))
			c.login(w, req)
			return
		}

		// https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token
		iss := payload.Claims["iss"]
		if iss != "accounts.google.com" && iss != "https://accounts.google.com" {
			w.Header().Add("X-sandrio-auth-message", fmt.Sprintf("Invalid iss found: %s", iss))
			c.login(w, req)
			return
		}

		user := payload.Claims["email"]
		for _, u := range c.AllowedUsers {
			if u != user {
				continue
			}
			logging.Print(logger, req, "Auth: Request authorized, forwarding to backend.")
			h.ServeHTTP(w, req)
			logging.Print(logger, req, "Auth: Got response. All done.")
			return
		}
		http.Error(w, fmt.Sprintf("%s does not have permission to view this page.", user), http.StatusForbidden)
	})
}

func (c *DomainConfig) login(w http.ResponseWriter, req *http.Request) {
	// Never cache this page. It's the login page, not the destination.
	w.Header().Add("Cache-Control", "no-cache")

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
		"Target":       req.URL.String(),
		"ReqDump":      string(reqDump),
		"Payload":      payload,
	})
}
