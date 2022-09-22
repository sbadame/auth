package main

import (
	"fmt"
	"html"
	"log"
	"net/http"

	"os"
)

func main() {
	// https://cloud.google.com/run/docs/reference/container-contract#port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8091"
	}
	log.Printf("Serving test server on %s.\n", port)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from the test server!, %q", html.EscapeString(r.URL.Path))
	})
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
