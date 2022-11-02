package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func WebAuthNValidateResponseHandler() http.Handler { return http.HandlerFunc(validateResponse) }
func WebAuthNValidateNewUserHandler() http.Handler  { return http.HandlerFunc(validateNewUser) }

// https://w3c.github.io/webauthn/#dictdef-authenticationresponsejson

type clientDataJSON struct {
	Challenge   string `json:"challenge"`
	CrossOrigin bool   `json:"crossOrigin"`
	Origin      string `json:"origin"`
	Type        string `json:"type"`
}

type authenticatorAssertionResponseJSON struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AuthenticatorData []byte `json:"authenticatorData"`
	Signature         []byte `json:"signature"`
	UserHandle        []byte `json:"userHandle"`
}

type authenticationResponseJSON struct {
	Id                      []byte                             `json:"id"`
	RawId                   []byte                             `json:"rawId"`
	Response                authenticatorAssertionResponseJSON `json:"response"`
	AuthenticatorAttachment string                             `json:"authenticatorAttachment"`
	ClientExtensionResults  string                             `json:"clientExtensionResults"`
	AuthenticationType      string                             `json:"type"`
}

type clientData struct {
	Challenge   string `json:"challenge"`
	CrossOrigin bool   `json:"crossOrigin"`
	Origin      string `json:"origin"`
	Type        string `json:"type"`
}

type authenticatorAttestationResponseJSON struct {
	AttestationObject []byte `json:"attestationObject"`
	ClientDataJSON    []byte `json:"clientDataJSON"`
}

type publicKeyCredentialJSON struct {
	AuthenticatorAttachment string                               `json:"authenticatorAttachment"`
	Id                      string                               `json:"id"`
	RawId                   string                               `json:"rawId"`
	Response                authenticatorAttestationResponseJSON `json:"response"`
	Type                    string                               `json:"type"`
}

type attestation struct {
	Fmt      string
	AuthData []byte
	AttStmt  map[string]interface{}
}

func decodeAttestation(b []byte) (*attestation, error) {
	m, remainingBytes, err := decodeCBOR(b)
	if err != nil {
		return nil, err
	}

	if len(remainingBytes) != 0 {
		return nil, fmt.Errorf("Bytes passed in were not fully consumed. %d bytes remain.", len(remainingBytes))
	}

	pairs, ok := m.([]pair)
	if !ok {
		return nil, errors.New("Expected a CBOR map at the highest level")
	}

	var a attestation
	for _, p := range pairs {
		if p.key == "fmt" {
			a.Fmt = p.value.(string)
		}
		if p.key == "authData" {
			a.AuthData = p.value.([]byte)
		}
		if p.key == "attStmt" {
			a.AttStmt = make(map[string]interface{})
			for _, p2 := range p.value.([]pair) {
				a.AttStmt[p2.key.(string)] = p2.value
			}
		}
	}
	return &a, nil
}

func validateNewUser(w http.ResponseWriter, r *http.Request) {
	// https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
	if r.Method != "POST" {
		http.Error(w, "Only POST is allowed for this request.", http.StatusMethodNotAllowed)
		return
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var pkCredential publicKeyCredentialJSON
	if err = json.Unmarshal(b, &pkCredential); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var cd clientData
	if err = json.Unmarshal(pkCredential.Response.ClientDataJSON, &cd); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := decodeAttestation(pkCredential.Response.AttestationObject); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, "{}")
}

func validateResponse(w http.ResponseWriter, r *http.Request) {
	// https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
	// https://goo.gl/yabPex

	if r.Method != "POST" {
		http.Error(w, "Only POST is allowed for this request.", http.StatusMethodNotAllowed)
		return
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var pkCredential authenticationResponseJSON
	if err = json.Unmarshal(b, &pkCredential); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if pkCredential.AuthenticatorAttachment != "cross-platform" {
		http.Error(w, "authenticator attachment must be cross-platform", http.StatusBadRequest)
		return
	}

	if pkCredential.AuthenticationType != "public-key" {
		http.Error(w, "type must be public-key", http.StatusBadRequest)
		return
	}

	var clientData clientDataJSON
	if err = json.Unmarshal(pkCredential.Response.ClientDataJSON, &clientData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Verifying that the challenge is the same as the challenge that was sent
	// TODO: Ensuring that the origin was the origin expected
	// TODO: Validating that the signature over the clientDataHash and the attestation using the certificate chain for that specific model of the authenticator
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, "{}")
}
