package iimpserver

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	ReadMessageRequestHTTPMethod = "POST"
	ReadMessageRequestRoutePath  = "/api/client/conversations/{conversationId}/messages/{messageId}/read"
)

// Mark a message as read by the authenticated user.
type ReadMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to. This is typically a UUIDv7.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message to mark as read. This is typically a UUIDv7.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth ReadMessageRequestAuthParams
}

type ReadMessageRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

// NewReadMessageRequest creates a new ReadMessageRequest from an http.Request and performs parameter parsing and validation.
func NewReadMessageRequest(w http.ResponseWriter, r *http.Request) (req ReadMessageRequest, err error) {

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

	return
}

type ReadMessage200Response struct {
}

// Message marked as read successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessage200Response(w http.ResponseWriter, response ReadMessage200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type ReadMessage400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessage400Response(w http.ResponseWriter, response ReadMessage400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type ReadMessage401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessage401Response(w http.ResponseWriter, response ReadMessage401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type ReadMessage403Response struct {
}

// Forbidden. The authenticated user is not a participant in the conversation or is not a recipient of the message.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessage403Response(w http.ResponseWriter, response ReadMessage403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type ReadMessage404Response struct {
}

// Conversation or message not found or Message not in the conversation id specified.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessage404Response(w http.ResponseWriter, response ReadMessage404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type ReadMessage500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReadMessage500Response(w http.ResponseWriter, response ReadMessage500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
