package reverseproxy

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// There is some header that is causing sporadic timeouts and 304's ugh.
// Purposefully lower-case to make it easy to do string comparisons.
var headersToForward = map[string]bool{
	"user-agent":      true,
	"accept":          true,
	"accept-encoding": true,
	"accept-language": true,
	"cache-control":   true,
}

type ReverseProxy struct {
	Backend *url.URL
	Client  *http.Client
	Logger  *log.Logger
}

// Tests the connection to the backend to confirm that the configuration is valid.
func (p *ReverseProxy) HealthCheck() error {

	var backendResp *http.Response
	var err error

	if backendResp, err = p.Client.Get(p.Backend.String()); err != nil {
		return fmt.Errorf("Unable to connect to a backend: %v", err)
	}

	backendResp.Body.Close()
	dump, err := httputil.DumpResponse(backendResp, false)
	if err != nil {
		return fmt.Errorf("Unable to dump response from backend: %v", err)
	}
	p.Logger.Printf("Backend %s Got response: %q", p.Backend, dump)
	return nil
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, feReq *http.Request) {

	// Concat the backend with the frontend's request path to get the URL for the backend.
	beURL, err := p.Backend.Parse(feReq.URL.String())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error creating URL for backend: %v", err.Error())
		return
	}

	// Create the http request to send to the backend.
	beReq, err := http.NewRequestWithContext(feReq.Context(), feReq.Method, beURL.String(), feReq.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error creating request for backend: %v", err.Error())
		return
	}

	// Copy headers from the frontend's request to the backend's request.
	for h, values := range feReq.Header {
		if !headersToForward[strings.ToLower(h)] {
			continue
		}
		for _, v := range values {
			beReq.Header.Add(h, v)
		}
	}

	// Log the final HTTP request being sent to the backend.
	dump, err := httputil.DumpRequest(beReq, true)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error dumping request to backend: %v", err.Error())
		return
	}
	p.Logger.Printf("Sending %q", dump)

	// Perform the request.
	backendResp, err := p.Client.Do(beReq)
	if err != nil {
		p.Logger.Fatalf("Got error from backend: %v", err)
	}
	defer backendResp.Body.Close()

	// Copy headers from the backend's response to the response.
	for key, values := range backendResp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	// Copy backendResp.Body into frontend's response writer.
	if _, err := io.Copy(w, backendResp.Body); err != nil {
		p.Logger.Fatalf("Got an error copying backend response to end user response. %v\n", err)
	}
}
