package logging

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
)

type entry struct {
	Message  string            `json:"message"`
	Severity string            `json:"severity,omitempty"`
	Labels   map[string]string `json:"logging.googleapis.com/labels,omitempty"`
	Trace    string            `json:"logging.googleapis.com/trace,omitempty"`
}

func (e *entry) init() {
	if e.Severity == "" {
		e.Severity = "INFO"
	}
	if e.Labels == nil {
		e.Labels = make(map[string]string)
	}
	e.Labels["pid"] = strconv.Itoa(os.Getpid())
	e.Labels["name"] = "auth-server"
}

func (e *entry) String() string {
	e.init()
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")

	var out []byte
	var err error
	if projectID != "" {
		out, err = json.MarshalIndent(e, "", "  ")
	} else {
		out, err = json.Marshal(e)
	}

	if err != nil {
		log.Printf("json.MarshalIndent: %v", err)
	}
	return string(out)
}

func Print(logger *log.Logger, r *http.Request, message string) {
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID != "" {
		traceHeader := r.Header.Get("X-Cloud-Trace-Context")
		traceParts := strings.Split(traceHeader, "/")
		if len(traceParts) > 0 && len(traceParts[0]) > 0 {
			trace := fmt.Sprintf("projects/%s/traces/%s", projectID, traceParts[0])
			logger.Println(entry{Message: message, Trace: trace})
			return
		}
	}
	logger.Println(message)
}

func Handler(logger *log.Logger, h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		dump, err := httputil.DumpRequest(req, false)
		if err != nil {
			logger.Fatalln(err.Error())
		}
		Print(logger, req, fmt.Sprintf("Request %q", dump))
		h.ServeHTTP(w, req)
	})
}
