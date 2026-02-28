package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	SignUpRequestHTTPMethod = "POST"
	SignUpRequestRoutePath  = "/api/client/signup"
)

// Register a new user account with the IIMP service.
type SignUpRequest struct {

	// Request body
	Body SignUpRequestBody
}

type SignUpRequestBody struct {

	// Optional display name for the user.
	//
	// Optional
	//
	DisplayName *string `json:"DisplayName,omitempty"`

	// Email address for the new account. This can be same as the user ID or a different email address. The email address will be used for account recovery.
	//
	// Required
	//
	// Must be non-empty
	Email string `json:"Email"`

	// Password for the new account.
	//
	// Required
	//
	// Must be non-empty
	Password string `json:"Password"`

	// Desired user ID for the new account. (localpart@domain). Domain must be the same as the server's domain.
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func NewSignUpRequestBody(data map[string]any) (SignUpRequestBody, error) {
	var body SignUpRequestBody

	valDisplayName, ok := data["DisplayName"]
	if !ok {

		// skip, leave as zero value

	} else {

		valDisplayNameTyped, ok := valDisplayName.(string)
		if !ok {
			return body, fmt.Errorf("field 'DisplayName' has incorrect type")
		}

		body.DisplayName = &valDisplayNameTyped

	}

	valEmail, ok := data["Email"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Email'")

	} else {

		valEmailTyped, ok := valEmail.(string)
		if !ok {
			return body, fmt.Errorf("field 'Email' has incorrect type")
		}

		valEmailTyped = strings.TrimSpace(valEmailTyped)
		if len(valEmailTyped) == 0 {
			return body, fmt.Errorf("field 'Email' must be non-empty")
		}

		body.Email = valEmailTyped

	}

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

// NewSignUpRequest creates a new SignUpRequest from an http.Request and performs parameter parsing and validation.
func NewSignUpRequest(w http.ResponseWriter, r *http.Request) (req SignUpRequest, err error) {

	bodyData := make(map[string]any)

	maxBodyBytes := int64(256 << 10) // 256 KB default limit

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err = json.NewDecoder(r.Body).Decode(&bodyData)
	if err != nil {
		return
	}
	var body SignUpRequestBody
	body, err = NewSignUpRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type SignUp201Response struct {
}

// Account created successfully. No user_id is returned in the response body. The client should use the user_id from the request for subsequent operations.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteSignUp201Response(w http.ResponseWriter, response SignUp201Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(201)
	return nil

}

type SignUp400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteSignUp400Response(w http.ResponseWriter, response SignUp400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type SignUp409Response struct {
}

// User ID already exists.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteSignUp409Response(w http.ResponseWriter, response SignUp409Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(409)
	return nil

}

type SignUp500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteSignUp500Response(w http.ResponseWriter, response SignUp500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
