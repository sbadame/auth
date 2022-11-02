package auth

import (
	"encoding/binary"
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

const (
	typeMask = 0b111_00000
	argsMask = 0b000_11111
)
const (
	typeUInt   uint8 = iota << 5
	typeNegInt uint8 = iota << 5
	typeBytes  uint8 = iota << 5
	typeText   uint8 = iota << 5
	typeArray  uint8 = iota << 5
	typeMap    uint8 = iota << 5
)

func decodeCBOR(b []byte) (interface{}, []byte, error) {
	switch b[0] & typeMask {
	case typeUInt:
		return parseUint(b)
	case typeNegInt:
		return parseNegInt(b)
	case typeText:
		return parseText(b)
	case typeArray:
		return parseArray(b)
	case typeBytes:
		return parseBytes(b)
	case typeMap:
		return parseMap(b)
	default:
		return nil, nil, fmt.Errorf("Unable to parse %b", b[0])
	}
}

func parseUint(b []byte) (uint64, []byte, error) {
	t := b[0] & typeMask
	if t != typeUInt {
		return 0, nil, fmt.Errorf("Uint type was not passed in, got %b.", b[0])
	}
	return uint64(b[0] & argsMask), b[1:], nil
}

func parseNegInt(b []byte) (int, []byte, error) {
	t := b[0] & typeMask
	if t != typeNegInt {
		return 0, nil, fmt.Errorf("NegInt type was not passed in, got %b.", b[0])
	}
	return -1 - int(b[0]&argsMask), b[1:], nil
}

func parseBytes(b []byte) ([]byte, []byte, error) {
	t := b[0] & typeMask
	if t != typeBytes {
		return nil, nil, fmt.Errorf("Bytes type was not passed in, got %b.", b[0])
	}

	length := 0
	arg := b[0] & argsMask
	if arg < 24 {
		length = int(arg)
		// b[0] is the type AND length
		return b[1 : 1+length], b[1+length:], nil
	}
	if arg == 24 {
		length = int(b[1])
		// b[0] is the type, b[1] is the # of bytes
		return b[2 : 2+length], b[2+length:], nil
	}
	if arg == 25 {
		length = int(binary.BigEndian.Uint16(b[1:3]))
		// b[0] is the type, b[1], b[2] are the # of bytes.
		return b[3 : 3+length], b[3+length:], nil
	}
	if arg == 26 {
		length = int(binary.BigEndian.Uint32(b[1:5]))
		// b[0] is the type, b[1], b[2], b[3], b[4] are the # of bytes.
		return b[5 : 5+length], b[5+length:], nil
	}
	if arg == 27 {
		length = int(binary.BigEndian.Uint64(b[1:9]))
		// b[0] is the type, b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8] are the # of bytes.
		return b[9 : 9+length], b[9+length:], nil
	}
	// arg > 27
	return nil, nil, fmt.Errorf("Can't parse really long byte strings: %b", b[0])
}

func parseText(b []byte) (string, []byte, error) {
	t := b[0] & typeMask
	if t != typeText {
		return "", nil, fmt.Errorf("Text type was not passed in, got %b.", b[0])
	}

	length := b[0] & argsMask
	if length == 31 {
		return "", nil, errors.New("Can't handle long strings.")
	}

	return string(b[1 : length+1]), b[length+1:], nil
}

func parseArray(b []byte) ([]interface{}, []byte, error) {
	if (b[0] & typeMask) != typeArray {
		return nil, nil, fmt.Errorf("Type is not an array: %b", b[0])
	}

	length := int(b[0] & argsMask)
	if length == 31 {
		return nil, nil, errors.New("Can't handle long arrays.")
	}

	arr := make([]interface{}, 0)
	remaining := b[1:]
	var item interface{}
	var err error
	for i := 0; i < length; i++ {
		item, remaining, err = decodeCBOR(remaining)
		if err != nil {
			return nil, nil, err
		}
		arr = append(arr, item)
	}
	return arr, remaining, nil
}

type pair struct {
	key, value interface{}
}

func parseMap(b []byte) ([]pair, []byte, error) {
	if (b[0] & typeMask) != typeMap {
		return nil, nil, fmt.Errorf("Type is not a map: %b", b[0])
	}

	length := int(b[0] & argsMask)
	if length == 31 {
		return nil, nil, errors.New("Don't know how to handle large maps.")
	}

	m := make([]pair, 0)
	remaining := b[1:]
	var key, val interface{}
	var err error
	for i := 0; i < length; i++ {
		key, remaining, err = decodeCBOR(remaining)
		if err != nil {
			return nil, nil, fmt.Errorf("Error parsing map key: %w", err)
		}

		val, remaining, err = decodeCBOR(remaining)
		if err != nil {
			return nil, nil, fmt.Errorf("Error parsing map value: %w", err)
		}

		p := pair{key, val}
		m = append(m, p)
	}
	return m, remaining, nil
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
		return nil, fmt.Errorf("Bytes passed in were not fully consumed.")
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
