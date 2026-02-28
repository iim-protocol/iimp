package iimpserver

import (
	"encoding/json"
	"net/http"
)

const (
	GetUserPublicKeyByIdRequestHTTPMethod = "GET"
	GetUserPublicKeyByIdRequestRoutePath  = "/.well-known/iimp/keys/users/{userId}/{keyId}"
)

// Retrieve a specific public key associated with a user, identified by its key ID. Used for historical key retrieval.
type GetUserPublicKeyByIdRequest struct {

	// Source: path parameter "{userId}"
	//

	// Unique identifier of the user whose public key is being requested. This should be in the format localpart@domain.
	//
	// Required
	UserId string

	// Source: path parameter "{keyId}"
	//

	// Unique identifier for the specific public key to retrieve. This allows clients to fetch historical keys if needed.
	//
	// Required
	KeyId string
}

// NewGetUserPublicKeyByIdRequest creates a new GetUserPublicKeyByIdRequest from an http.Request and performs parameter parsing and validation.
func NewGetUserPublicKeyByIdRequest(w http.ResponseWriter, r *http.Request) (req GetUserPublicKeyByIdRequest, err error) {

	valUserId, err := parsestringParam(r.PathValue("userId"), "path: userId", true)
	if err != nil {
		return
	}

	req.UserId = *valUserId

	valKeyId, err := parsestringParam(r.PathValue("keyId"), "path: keyId", true)
	if err != nil {
		return
	}

	req.KeyId = *valKeyId

	return
}

type GetUserPublicKeyById200Response struct {

	// Response body
	Body GetUserPublicKeyById200ResponseBody
}

type GetUserPublicKeyById200ResponseBody struct {

	// Unique identifier for the public key.
	//
	// Required
	//
	// Must be non-empty
	KeyId string `json:"KeyId"`

	// The actual public key data, encoded in a suitable format (X25519 public key encoded in Base64URL format).
	//
	// Required
	//
	// Must be non-empty
	PublicKey string `json:"PublicKey"`

	// Timestamp indicating when the public key was uploaded, in ISO 8601 format.
	//
	// Required
	//
	// Must be non-empty
	UploadedAt string `json:"UploadedAt"`

	// Unique identifier of the user to whom the public key belongs. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

// Successful retrieval of the user's public key information.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetUserPublicKeyById200Response(w http.ResponseWriter, response GetUserPublicKeyById200Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(200)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type GetUserPublicKeyById404Response struct {
}

// No public key found for the specified user and key ID or the user does not exist.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetUserPublicKeyById404Response(w http.ResponseWriter, response GetUserPublicKeyById404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type GetUserPublicKeyById500Response struct {
}

// Internal server error while retrieving the user's public key information.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetUserPublicKeyById500Response(w http.ResponseWriter, response GetUserPublicKeyById500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
