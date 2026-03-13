package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	AddPublicKeyRequestHTTPMethod = "POST"
	AddPublicKeyRequestRoutePath  = "/iimp/api/client/keys"
)

// Add a new public key for end-to-end encryption.
type AddPublicKeyRequest struct {

	// Authentication parameters
	Auth AddPublicKeyRequestAuthParams

	// Request body
	Body AddPublicKeyRequestBody
}

type AddPublicKeyRequestBody struct {

	// A unique identifier for the uploaded public key. This ID can be used to reference the key in future operations, such as encrypting messages for specific recipients or managing keys.
	//
	// Required
	//
	// Must be non-empty
	KeyId string `json:"KeyId"`

	// The public key to be added for end-to-end encryption. The key should be Base64URL Encoded X25519 Key.
	//
	// Required
	//
	// Must be non-empty
	PublicKey string `json:"PublicKey"`

	// Timestamp of key upload. Format => RFC3339.
	//
	// Required
	//
	// Must be non-empty
	Timestamp string `json:"Timestamp"`
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

	valKeyId, ok := data["KeyId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'KeyId'")

	} else {

		valKeyIdTyped, ok := valKeyId.(string)
		if !ok {
			return body, fmt.Errorf("field 'KeyId' has incorrect type")
		}

		valKeyIdTyped = strings.TrimSpace(valKeyIdTyped)
		if len(valKeyIdTyped) == 0 {
			return body, fmt.Errorf("field 'KeyId' must be non-empty")
		}

		body.KeyId = valKeyIdTyped

	}

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

	valTimestamp, ok := data["Timestamp"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Timestamp'")

	} else {

		valTimestampTyped, ok := valTimestamp.(string)
		if !ok {
			return body, fmt.Errorf("field 'Timestamp' has incorrect type")
		}

		valTimestampTyped = strings.TrimSpace(valTimestampTyped)
		if len(valTimestampTyped) == 0 {
			return body, fmt.Errorf("field 'Timestamp' must be non-empty")
		}

		body.Timestamp = valTimestampTyped

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
}

// Public key added successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteAddPublicKey201Response(w http.ResponseWriter, response AddPublicKey201Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(201)
	return nil

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
