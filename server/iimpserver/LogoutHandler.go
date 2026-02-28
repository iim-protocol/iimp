package iimpserver

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	LogoutRequestHTTPMethod = "POST"
	LogoutRequestRoutePath  = "/api/client/logout"
)

// Log out the current user and invalidate the session.
type LogoutRequest struct {

	// Authentication parameters
	Auth LogoutRequestAuthParams
}

type LogoutRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

// NewLogoutRequest creates a new LogoutRequest from an http.Request and performs parameter parsing and validation.
func NewLogoutRequest(w http.ResponseWriter, r *http.Request) (req LogoutRequest, err error) {

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

	return
}

type Logout204Response struct {
}

// Logout successful. The session token is invalidated.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteLogout204Response(w http.ResponseWriter, response Logout204Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(204)
	return nil

}

type Logout401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteLogout401Response(w http.ResponseWriter, response Logout401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type Logout500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteLogout500Response(w http.ResponseWriter, response Logout500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
