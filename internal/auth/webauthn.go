package auth

import (
	"fmt"
	"net/http"
)

func WebAuthNValidateResponseHandler() http.Handler { return http.HandlerFunc(validateResponse) }

func validateResponse(w http.ResponseWriter, r *http.Request) {
	// TODO: Verifying that the challenge is the same as the challenge that was sent
	// TODO: Ensuring that the origin was the origin expected
	// TODO: Validating that the signature over the clientDataHash and the attestation using the certificate chain for that specific model of the authenticator
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, "{}")
}
