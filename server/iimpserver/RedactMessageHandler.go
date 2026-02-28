package iimpserver

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	RedactMessageRequestHTTPMethod = "POST"
	RedactMessageRequestRoutePath  = "/api/client/conversations/{conversationId}/messages/{messageId}/redact"
)

// Redact a message in a conversation. If this conversation is a Direct Conversation, only the sender of the message can redact it. If this conversation is a Group Conversation, only the sender of the message or the owner of the conversation can redact it.
type RedactMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to. This is typically a UUIDv7.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message to redact. This is typically a UUIDv7.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth RedactMessageRequestAuthParams
}

type RedactMessageRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

// NewRedactMessageRequest creates a new RedactMessageRequest from an http.Request and performs parameter parsing and validation.
func NewRedactMessageRequest(w http.ResponseWriter, r *http.Request) (req RedactMessageRequest, err error) {

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

type RedactMessage200Response struct {
}

// Message redacted successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessage200Response(w http.ResponseWriter, response RedactMessage200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type RedactMessage400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessage400Response(w http.ResponseWriter, response RedactMessage400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type RedactMessage401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessage401Response(w http.ResponseWriter, response RedactMessage401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type RedactMessage403Response struct {
}

// Forbidden. The authenticated user is not the sender of the message or the owner of the conversation.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessage403Response(w http.ResponseWriter, response RedactMessage403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type RedactMessage404Response struct {
}

// Conversation or message not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessage404Response(w http.ResponseWriter, response RedactMessage404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type RedactMessage500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessage500Response(w http.ResponseWriter, response RedactMessage500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
