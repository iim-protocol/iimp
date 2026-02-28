package iimpserver

import (
	"encoding/json"
	"net/http"
)

const (
	GetJWKSStoreRequestHTTPMethod = "GET"
	GetJWKSStoreRequestRoutePath  = "/.well-known/iimp/jwks"
)

// Retrieve the JSON Web Key Set (JWKS) containing the public keys used by the server for verifying signatures. This is used in the federation process to ensure secure communication between servers.
type GetJWKSStoreRequest struct {
}

// NewGetJWKSStoreRequest creates a new GetJWKSStoreRequest from an http.Request and performs parameter parsing and validation.
func NewGetJWKSStoreRequest(w http.ResponseWriter, r *http.Request) (req GetJWKSStoreRequest, err error) {

	return
}

type GetJWKSStore200Response struct {

	// Response body
	Body GetJWKSStore200ResponseBody
}

type GetJWKSStore200ResponseBodyKeysItem struct {

	// The algorithm used with this key. For example, "RS256" or "EdDSA".
	//
	// Required
	//
	// Must be non-empty
	Alg string `json:"Alg"`

	// Elliptic curve name (e.g., "Ed25519" or "X25519"). Required if Kty is "OKP".
	//
	// Optional
	//
	Crv *string `json:"Crv,omitempty"`

	// RSA public exponent (base64url encoded). Required if Kty is "RSA".
	//
	// Optional
	//
	E *string `json:"E,omitempty"`

	// Unique identifier for the key. Used to match the 'kid' field in JWT headers.
	//
	// Required
	//
	// Must be non-empty
	Kid string `json:"Kid"`

	// The key type. For example, "RSA" or "OKP".
	//
	// Required
	//
	// Must be non-empty
	Kty string `json:"Kty"`

	// RSA modulus (base64url encoded). Required if Kty is "RSA".
	//
	// Optional
	//
	N *string `json:"N,omitempty"`

	// The intended use of the key. Typically "sig" for signature verification.
	//
	// Required
	//
	// Must be non-empty
	Use string `json:"Use"`

	// Public key value (base64url encoded). Required if Kty is "OKP".
	//
	// Optional
	//
	X *string `json:"X,omitempty"`
}

type GetJWKSStore200ResponseBody struct {

	// A list of JSON Web Keys (JWK) used to verify signatures issued by this server.
	//
	// Required
	//
	// Must be non-empty
	Keys []GetJWKSStore200ResponseBodyKeysItem `json:"Keys"`
}

// Successful retrieval of the JWKS information. RFC7517 compliant response containing the public keys used for signature verification.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetJWKSStore200Response(w http.ResponseWriter, response GetJWKSStore200Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(200)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type GetJWKSStore500Response struct {
}

// Internal server error while retrieving the JWKS information.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetJWKSStore500Response(w http.ResponseWriter, response GetJWKSStore500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
