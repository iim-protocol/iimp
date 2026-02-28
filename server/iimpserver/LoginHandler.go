package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	LoginRequestHTTPMethod = "POST"
	LoginRequestRoutePath  = "/api/client/login"
)

// Authenticate a user and establish a session.
type LoginRequest struct {

	// Request body
	Body LoginRequestBody
}

type LoginRequestBody struct {

	// Password for the account.
	//
	// Required
	//
	// Must be non-empty
	Password string `json:"Password"`

	// User ID for the account. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func NewLoginRequestBody(data map[string]any) (LoginRequestBody, error) {
	var body LoginRequestBody

	valPassword, ok := data["Password"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Password'")

	} else {

		valPasswordTyped, ok := valPassword.(string)
		if !ok {
			return body, fmt.Errorf("field 'Password' has incorrect type")
		}

		valPasswordTyped = strings.TrimSpace(valPasswordTyped)
		if len(valPasswordTyped) == 0 {
			return body, fmt.Errorf("field 'Password' must be non-empty")
		}

		body.Password = valPasswordTyped

	}

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

// NewLoginRequest creates a new LoginRequest from an http.Request and performs parameter parsing and validation.
func NewLoginRequest(w http.ResponseWriter, r *http.Request) (req LoginRequest, err error) {

	bodyData := make(map[string]any)

	maxBodyBytes := int64(256 << 10) // 256 KB default limit

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err = json.NewDecoder(r.Body).Decode(&bodyData)
	if err != nil {
		return
	}
	var body LoginRequestBody
	body, err = NewLoginRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type Login200Response struct {
}

// Successful operation.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteLogin200Response(w http.ResponseWriter, response Login200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type Login400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteLogin400Response(w http.ResponseWriter, response Login400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type Login401Response struct {
}

// Unauthorized. Invalid user ID or password.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteLogin401Response(w http.ResponseWriter, response Login401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type Login500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteLogin500Response(w http.ResponseWriter, response Login500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
