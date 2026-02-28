package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	SyncUserEventsRequestHTTPMethod = "GET"
	SyncUserEventsRequestRoutePath  = "/api/client/events/sync"
)

// Fetch a list of events for the authenticated user.
type SyncUserEventsRequest struct {

	// Source: query parameter "cursor"
	//

	// A cursor (Monotonically increasing per-user sequence number) for pagination. The server will return events starting from this cursor. If not provided, the server will return all available events starting from the oldest event in the system. The response will include a next_cursor field that can be used to fetch the next page of results.
	//
	// Optional
	Cursor *float64

	// Source: query parameter "limit"
	//

	// The maximum number of events to return in the response. If not provided, the server will use a default limit (e.g., 50). The server may enforce a maximum limit (100) to prevent excessively large responses.
	//
	// Optional
	Limit *float64

	// Authentication parameters
	Auth SyncUserEventsRequestAuthParams
}

type SyncUserEventsRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

// NewSyncUserEventsRequest creates a new SyncUserEventsRequest from an http.Request and performs parameter parsing and validation.
func NewSyncUserEventsRequest(w http.ResponseWriter, r *http.Request) (req SyncUserEventsRequest, err error) {

	valCursor, err := parsefloat64Param(r.URL.Query().Get("cursor"), "query: cursor", false)
	if err != nil {
		return
	}

	req.Cursor = valCursor

	valLimit, err := parsefloat64Param(r.URL.Query().Get("limit"), "query: limit", false)
	if err != nil {
		return
	}

	req.Limit = valLimit

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

type SyncUserEvents200Response struct {

	// Response body
	Body SyncUserEvents200ResponseBody
}

type SyncUserEvents200ResponseBodyEventsItem struct {

	// The timestamp when the event was created. Format => ISO 8601 (e.g., "2024-06-01T12:00:00Z").
	//
	// Required
	//
	// Must be non-empty
	CreatedAt string `json:"CreatedAt"`

	// A unique identifier for the event (Monotonically increasing per-user sequence number).
	//
	// Required
	//
	EventId float64 `json:"EventId"`

	// The type of the event (e.g., "message_received", "conversation_created", etc.). This field can be used by the client to determine how to process the event. For a full list of event types and their corresponding payload structures, refer to the IIMP Client Events documentation [here](https://github.com/iim-protocol/iimp/tree/main/Events.md).
	//
	// Required
	//
	// Must be non-empty
	EventType string `json:"EventType"`

	// An optional field containing additional data related to the event. The structure of this object can vary depending on the event type and must conform to the IIMP Client Events documentation. Clients should be designed to handle different payload structures based on the event type.
	//
	// Optional
	//
	Payload *map[string]any `json:"Payload,omitempty"`
}

type SyncUserEvents200ResponseBody struct {

	// A list of events for the authenticated user, if any available. The events are ordered by their EventId in Ascending Order. The server may return up to 'limit' events in the response. If there are more events available beyond the returned list, a 'next_cursor' field will be included in the response, which can be used to fetch the next page of results.
	//
	// Required
	//
	Events []SyncUserEvents200ResponseBodyEventsItem `json:"Events"`

	// A cursor for the next page of results, if available. This field will be included in the response if there are more events available beyond the returned list.
	//
	// Optional
	//
	NextCursor *float64 `json:"NextCursor,omitempty"`
}

// Events fetched successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteSyncUserEvents200Response(w http.ResponseWriter, response SyncUserEvents200Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(200)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type SyncUserEvents401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteSyncUserEvents401Response(w http.ResponseWriter, response SyncUserEvents401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type SyncUserEvents500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteSyncUserEvents500Response(w http.ResponseWriter, response SyncUserEvents500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
