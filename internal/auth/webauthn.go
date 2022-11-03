package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type WebAuthn struct {
	RpID, Origin string
}

func WebAuthNValidateResponseHandler() http.Handler { return http.HandlerFunc(validateResponse) }

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
	ClientDataJSON []byte `json:"clientDataJSON"`

	AttestationObject  []byte `json:"attestationObject"`
	PublicKey          []byte `json:"publicKey"`
	PublicKeyAlgorithm int    `json:"publicKeyAlgorithm"`
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

func (w *WebAuthn) NewUserHandler() http.HandlerFunc {
	return http.HandlerFunc(w.validateNewUser)
}

func (web *WebAuthn) validateNewUser(w http.ResponseWriter, r *http.Request) {
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

	// Step 7
	if cd.Type != "webauthn.create" {
		http.Error(w, fmt.Sprintf("Client data type was not webauthn.create, instead got %s", cd.Type), http.StatusBadRequest)
		return
	}

	// Step 8
	// TODO: Verify the the base64 encoding of cd.Challenge is the same as the challenge given.

	// Step 9
	if cd.Origin != web.Origin {
		http.Error(w, fmt.Sprintf("Client origin is not %s, instead got %s", web.Origin, cd.Origin), http.StatusBadRequest)
		return
	}

	// Step 11
	a, err := decodeAttestation(pkCredential.Response.AttestationObject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Step 12
	// https://w3c.github.io/webauthn/#authenticator-data
	rpidHash := *(*[32]byte)(a.AuthData[0:32])
	if rpidHash != sha256.Sum256([]byte(web.RpID)) {
		http.Error(w, fmt.Sprintf("rpIdHash is not for Rp ID: %s", web.RpID), http.StatusBadRequest)
		return
	}

	// TODO: Actually consider these considerations: https://w3c.github.io/webauthn/#sctn-credential-backup

	// Step 17
	// I'm not sure whether this what I'm actually supposed to do, but it's hard to support self-attestation and
	// direct...
	alg := a.AttStmt["alg"]
	if alg == nil {
		alg = pkCredential.Response.PublicKeyAlgorithm
	}
	if alg != -7 && alg != -257 {
		http.Error(w, fmt.Sprintf("alg is not ES256 or RS256 (-7 or -257), got %v", a.AttStmt), http.StatusBadRequest)
		return
	}

	// Step 18
	// TODO: Verify client extension outputs.

	// Step 19
	// https://www.iana.org/assignments/webauthn/webauthn.xhtml has the list of approved formats.
	// Right now, I only support "packed" and "none"
	if a.Fmt != "packed" && a.Fmt != "none" {
		http.Error(w, "packed or none are the only supported formats.", http.StatusBadRequest)
		return
	}

	// Step 20
	// Perform the verification steps defined by `packed` or `none`.
	// https://w3c.github.io/webauthn/#sctn-packed-attestation

	if a.Fmt == "none" {
		_, err := x509.ParsePKIXPublicKey(pkCredential.Response.PublicKey)
		if err != nil {
			http.Error(w, "Failed to parse public key: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Step 21 (Step 1)
	if a.Fmt == "packed" {
		_, ok := a.AttStmt["alg"]
		if !ok {
			http.Error(w, fmt.Sprintf("No alg defined in the AttStmt: %v\n", a.AttStmt), http.StatusBadRequest)
			return
		}

		sig, ok := a.AttStmt["sig"]
		if !ok {
			http.Error(w, fmt.Sprintf("No sig defined in the AttStmt: %v\n", a.AttStmt), http.StatusBadRequest)
			return
		}

		x5c, ok := a.AttStmt["x5c"]
		if !ok {
			http.Error(w, fmt.Sprintf("No x5c defined in the AttStmt: %v\n", a.AttStmt), http.StatusBadRequest)
			return
		}
		b, ok := x5c.([]interface{})
		if !ok {
			http.Error(w, "Expected x5c to be an array.", http.StatusBadRequest)
			return
		}

		if len(b) != 1 {
			http.Error(w, fmt.Sprintf("Expected x5c to be an array with a single entry. (%d)", len(b)), http.StatusBadRequest)
			return
		}

		der, ok := b[0].([]byte)
		if !ok {
			http.Error(w, "Expected x5c[0] to be a byte string.", http.StatusBadRequest)
			return
		}

		// I'm not really sure if it makes sense to verify that this really came from a YubiKey
		// but it's fun, lets see how far I can go...
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			http.Error(w, fmt.Sprintf("Unable to parse x509 cert: %s", der), http.StatusBadRequest)
			return
		}

		if err = VerifyYubikeyCert(*cert); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		clientDataHash := sha256.Sum256(pkCredential.Response.ClientDataJSON)

		signedData := make([]byte, 0)
		signedData = append(signedData, a.AuthData...)
		signedData = append(signedData, clientDataHash[:]...)

		if err = cert.CheckSignature(x509.ECDSAWithSHA256, signedData, sig.([]byte)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

	}

	// Step 22
	// Assess the trustworthyness of the attestation from Step 20 to check that the key chains to a trusted root.

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
