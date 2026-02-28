package iimpserver

import (
	"encoding/json"
	"net/http"
)

const (
	DiscoverServerRequestHTTPMethod = "GET"
	DiscoverServerRequestRoutePath  = "/.well-known/iimp"
)

// Retrieve information about the IIMP server, including protocol version, domain, and federation endpoint. This allows clients and other servers to discover the capabilities and federation details of the server.
type DiscoverServerRequest struct {
}

// NewDiscoverServerRequest creates a new DiscoverServerRequest from an http.Request and performs parameter parsing and validation.
func NewDiscoverServerRequest(w http.ResponseWriter, r *http.Request) (req DiscoverServerRequest, err error) {

	return
}

type DiscoverServer200Response struct {

	// Response body
	Body DiscoverServer200ResponseBody
}

type DiscoverServer200ResponseBody struct {

	// Canonical domain name of the server.
	//
	// Required
	//
	// Must be non-empty
	Domain string `json:"Domain"`

	// URL endpoint for federation with other IIMP servers.
	//
	// Required
	//
	// Must be non-empty
	FederationEndpoint string `json:"FederationEndpoint"`

	// IIMP protocol version supported by the server.
	//
	// Required
	//
	// Must be non-empty
	Version string `json:"Version"`
}

// Successful retrieval of the server information. RFC8615 compliant response containing the server's protocol version, domain, and federation endpoint.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteDiscoverServer200Response(w http.ResponseWriter, response DiscoverServer200Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(200)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type DiscoverServer500Response struct {
}

// Internal server error while retrieving the server information.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteDiscoverServer500Response(w http.ResponseWriter, response DiscoverServer500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
