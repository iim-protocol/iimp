package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	RequestResetPasswordRequestHTTPMethod = "POST"
	RequestResetPasswordRequestRoutePath  = "/api/client/request-reset-password"
)

// Request a password reset for the user account.
type RequestResetPasswordRequest struct {

	// Request body
	Body RequestResetPasswordRequestBody
}

type RequestResetPasswordRequestBody struct {

	// User ID for the account.
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func NewRequestResetPasswordRequestBody(data map[string]any) (RequestResetPasswordRequestBody, error) {
	var body RequestResetPasswordRequestBody

	valUserId, ok := data["UserId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'UserId'")

	} else {

		valUserIdTyped, ok := valUserId.(string)
		if !ok {
			return body, fmt.Errorf("field 'UserId' has incorrect type")
		}

		valUserIdTyped = strings.TrimSpace(valUserIdTyped)
		if len(valUserIdTyped) == 0 {
			return body, fmt.Errorf("field 'UserId' must be non-empty")
		}

		body.UserId = valUserIdTyped

	}

	return body, nil
}

// NewRequestResetPasswordRequest creates a new RequestResetPasswordRequest from an http.Request and performs parameter parsing and validation.
func NewRequestResetPasswordRequest(w http.ResponseWriter, r *http.Request) (req RequestResetPasswordRequest, err error) {

	bodyData := make(map[string]any)

	maxBodyBytes := int64(256 << 10) // 256 KB default limit

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err = json.NewDecoder(r.Body).Decode(&bodyData)
	if err != nil {
		return
	}
	var body RequestResetPasswordRequestBody
	body, err = NewRequestResetPasswordRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type RequestResetPassword200Response struct {
}

// Password reset requested successfully. An email with reset instructions will be sent to the user's registered email address if the user ID exists. For security reasons, the response is the same regardless of whether the user ID exists or not.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRequestResetPassword200Response(w http.ResponseWriter, response RequestResetPassword200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type RequestResetPassword400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRequestResetPassword400Response(w http.ResponseWriter, response RequestResetPassword400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type RequestResetPassword500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRequestResetPassword500Response(w http.ResponseWriter, response RequestResetPassword500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
