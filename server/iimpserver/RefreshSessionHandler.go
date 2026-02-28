package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	RefreshSessionRequestHTTPMethod = "POST"
	RefreshSessionRequestRoutePath  = "/api/client/refresh-session"
)

// Refresh the session token.
type RefreshSessionRequest struct {

	// Request body
	Body RefreshSessionRequestBody
}

type RefreshSessionRequestBody struct {

	// A token used to refresh the session token when it expires.
	//
	// Required
	//
	// Must be non-empty
	RefreshToken string `json:"RefreshToken"`
}

func NewRefreshSessionRequestBody(data map[string]any) (RefreshSessionRequestBody, error) {
	var body RefreshSessionRequestBody

	valRefreshToken, ok := data["RefreshToken"]
	if !ok {

		return body, fmt.Errorf("missing required field 'RefreshToken'")

	} else {

		valRefreshTokenTyped, ok := valRefreshToken.(string)
		if !ok {
			return body, fmt.Errorf("field 'RefreshToken' has incorrect type")
		}

		valRefreshTokenTyped = strings.TrimSpace(valRefreshTokenTyped)
		if len(valRefreshTokenTyped) == 0 {
			return body, fmt.Errorf("field 'RefreshToken' must be non-empty")
		}

		body.RefreshToken = valRefreshTokenTyped

	}

	return body, nil
}

// NewRefreshSessionRequest creates a new RefreshSessionRequest from an http.Request and performs parameter parsing and validation.
func NewRefreshSessionRequest(w http.ResponseWriter, r *http.Request) (req RefreshSessionRequest, err error) {

	bodyData := make(map[string]any)

	maxBodyBytes := int64(256 << 10) // 256 KB default limit

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err = json.NewDecoder(r.Body).Decode(&bodyData)
	if err != nil {
		return
	}
	var body RefreshSessionRequestBody
	body, err = NewRefreshSessionRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type RefreshSession200Response struct {
}

// Successful operation.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRefreshSession200Response(w http.ResponseWriter, response RefreshSession200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type RefreshSession401Response struct {
}

// Unauthorized. No valid refresh token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRefreshSession401Response(w http.ResponseWriter, response RefreshSession401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type RefreshSession500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRefreshSession500Response(w http.ResponseWriter, response RefreshSession500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
