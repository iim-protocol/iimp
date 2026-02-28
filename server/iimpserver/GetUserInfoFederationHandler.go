package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	GetUserInfoFederationRequestHTTPMethod = "GET"
	GetUserInfoFederationRequestRoutePath  = "/api/federation/users/{userId}"
)

// \"FEDERATION\" Retrieve information about a user for federation purposes. This endpoint is used by other servers to fetch details about a user, such as their display name and more.
type GetUserInfoFederationRequest struct {

	// Source: path parameter "{userId}"
	//

	// Unique identifier of the user whose information is being requested. This should be in the format localpart@domain.
	//
	// Required
	UserId string

	// Authentication parameters
	Auth GetUserInfoFederationRequestAuthParams
}

type GetUserInfoFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

// NewGetUserInfoFederationRequest creates a new GetUserInfoFederationRequest from an http.Request and performs parameter parsing and validation.
func NewGetUserInfoFederationRequest(w http.ResponseWriter, r *http.Request) (req GetUserInfoFederationRequest, err error) {

	valUserId, err := parsestringParam(r.PathValue("userId"), "path: userId", true)
	if err != nil {
		return
	}

	req.UserId = *valUserId

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

type GetUserInfoFederation200Response struct {

	// Response body
	Body GetUserInfoFederation200ResponseBody
}

type GetUserInfoFederation200ResponseBody struct {

	// Display name of the user.
	//
	// Required
	//
	// Must be non-empty
	DisplayName string `json:"DisplayName"`

	// User ID of the user. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

// Successful retrieval of the user's information for federation purposes.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetUserInfoFederation200Response(w http.ResponseWriter, response GetUserInfoFederation200Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(200)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type GetUserInfoFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetUserInfoFederation401Response(w http.ResponseWriter, response GetUserInfoFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type GetUserInfoFederation404Response struct {
}

// User not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetUserInfoFederation404Response(w http.ResponseWriter, response GetUserInfoFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type GetUserInfoFederation500Response struct {
}

// Internal server error while retrieving the user's information.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteGetUserInfoFederation500Response(w http.ResponseWriter, response GetUserInfoFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
