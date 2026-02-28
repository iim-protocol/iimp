package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	AddPublicKeyRequestHTTPMethod = "POST"
	AddPublicKeyRequestRoutePath  = "/api/client/keys"
)

// Add a new public key for end-to-end encryption.
type AddPublicKeyRequest struct {

	// Authentication parameters
	Auth AddPublicKeyRequestAuthParams

	// Request body
	Body AddPublicKeyRequestBody
}

type AddPublicKeyRequestBody struct {

	// The public key to be added for end-to-end encryption. The key should be Base64URL Encoded X25519 Key.
	//
	// Required
	//
	// Must be non-empty
	PublicKey string `json:"PublicKey"`
}

type AddPublicKeyRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewAddPublicKeyRequestBody(data map[string]any) (AddPublicKeyRequestBody, error) {
	var body AddPublicKeyRequestBody

	valPublicKey, ok := data["PublicKey"]
	if !ok {

		return body, fmt.Errorf("missing required field 'PublicKey'")

	} else {

		valPublicKeyTyped, ok := valPublicKey.(string)
		if !ok {
			return body, fmt.Errorf("field 'PublicKey' has incorrect type")
		}

		valPublicKeyTyped = strings.TrimSpace(valPublicKeyTyped)
		if len(valPublicKeyTyped) == 0 {
			return body, fmt.Errorf("field 'PublicKey' must be non-empty")
		}

		body.PublicKey = valPublicKeyTyped

	}

	return body, nil
}

// NewAddPublicKeyRequest creates a new AddPublicKeyRequest from an http.Request and performs parameter parsing and validation.
func NewAddPublicKeyRequest(w http.ResponseWriter, r *http.Request) (req AddPublicKeyRequest, err error) {

	valAuthorization := r.Header.Get("Authorization")
	valAuthorization = strings.TrimSpace(valAuthorization)
	if valAuthorization == "" {
		req.Auth.Authorization = nil
	} else {
		req.Auth.Authorization = &valAuthorization
	}

	// Authentication parameters validation
	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		err = fmt.Errorf("missing required authentication parameter: Authorization")
		return
	}

	bodyData := make(map[string]any)

	maxBodyBytes := int64(256 << 10) // 256 KB default limit

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err = json.NewDecoder(r.Body).Decode(&bodyData)
	if err != nil {
		return
	}
	var body AddPublicKeyRequestBody
	body, err = NewAddPublicKeyRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type AddPublicKey201Response struct {

	// Response body
	Body AddPublicKey201ResponseBody
}

type AddPublicKey201ResponseBody struct {

	// A unique identifier for the uploaded public key. This ID can be used to reference the key in future operations, such as encrypting messages for specific recipients or managing keys.
	//
	// Required
	//
	// Must be non-empty
	KeyId string `json:"KeyId"`

	// The timestamp when the public key was uploaded to the server. This can be used to determine the age of the key and manage key rotation policies.
	//
	// Required
	//
	UploadedAt string `json:"UploadedAt"`
}

// Public key added successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteAddPublicKey201Response(w http.ResponseWriter, response AddPublicKey201Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(201)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type AddPublicKey400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteAddPublicKey400Response(w http.ResponseWriter, response AddPublicKey400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type AddPublicKey401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteAddPublicKey401Response(w http.ResponseWriter, response AddPublicKey401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type AddPublicKey500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteAddPublicKey500Response(w http.ResponseWriter, response AddPublicKey500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
