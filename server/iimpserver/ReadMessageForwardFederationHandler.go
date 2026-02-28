package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	ReadMessageForwardFederationRequestHTTPMethod = "POST"
	ReadMessageForwardFederationRequestRoutePath  = "/api/federation/conversations/{conversationId}/messages/{messageId}/read/forward"
)

// \"FEDERATION\" Mark a message as read in a conversation on another server.
type ReadMessageForwardFederationRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// Unique identifier of the conversation to mark the message as read in.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// Unique identifier of the message to mark as read.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth ReadMessageForwardFederationRequestAuthParams

	// Request body
	Body ReadMessageForwardFederationRequestBody
}

type ReadMessageForwardFederationRequestBody struct {

	// User ID of the user who read the message. This should be in the format localpart@domain and must belong to the requesting server.
	//
	// Required
	//
	// Must be non-empty
	ReaderUserId string `json:"ReaderUserId"`
}

type ReadMessageForwardFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewReadMessageForwardFederationRequestBody(data map[string]any) (ReadMessageForwardFederationRequestBody, error) {
	var body ReadMessageForwardFederationRequestBody

	valReaderUserId, ok := data["ReaderUserId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ReaderUserId'")

	} else {

		valReaderUserIdTyped, ok := valReaderUserId.(string)
		if !ok {
			return body, fmt.Errorf("field 'ReaderUserId' has incorrect type")
		}

		valReaderUserIdTyped = strings.TrimSpace(valReaderUserIdTyped)
		if len(valReaderUserIdTyped) == 0 {
			return body, fmt.Errorf("field 'ReaderUserId' must be non-empty")
		}

		body.ReaderUserId = valReaderUserIdTyped

	}

	return body, nil
}

// NewReadMessageForwardFederationRequest creates a new ReadMessageForwardFederationRequest from an http.Request and performs parameter parsing and validation.
func NewReadMessageForwardFederationRequest(w http.ResponseWriter, r *http.Request) (req ReadMessageForwardFederationRequest, err error) {

	valConversationId, err := parsestringParam(r.PathValue("conversationId"), "path: conversationId", true)
	if err != nil {
		return
	}

	req.ConversationId = *valConversationId

	valMessageId, err := parsestringParam(r.PathValue("messageId"), "path: messageId", true)
	if err != nil {
		return
	}

	req.MessageId = *valMessageId

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
	var body ReadMessageForwardFederationRequestBody
	body, err = NewReadMessageForwardFederationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type ReadMessageForwardFederation200Response struct {
}

// Message marked as read successfully from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessageForwardFederation200Response(w http.ResponseWriter, response ReadMessageForwardFederation200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type ReadMessageForwardFederation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessageForwardFederation400Response(w http.ResponseWriter, response ReadMessageForwardFederation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type ReadMessageForwardFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessageForwardFederation401Response(w http.ResponseWriter, response ReadMessageForwardFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type ReadMessageForwardFederation403Response struct {
}

// Forbidden. Requesting server's JWT is not valid (JWT iss domain != ReaderUserId domain) or ReaderUserId does not belong to the requesting server, OR the receiving server is not the conversation owner's server.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessageForwardFederation403Response(w http.ResponseWriter, response ReadMessageForwardFederation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type ReadMessageForwardFederation404Response struct {
}

// Conversation or message not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessageForwardFederation404Response(w http.ResponseWriter, response ReadMessageForwardFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type ReadMessageForwardFederation500Response struct {
}

// Internal server error while marking the message as read from federation requested.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessageForwardFederation500Response(w http.ResponseWriter, response ReadMessageForwardFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
