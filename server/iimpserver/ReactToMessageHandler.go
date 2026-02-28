package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	ReactToMessageRequestHTTPMethod = "POST"
	ReactToMessageRequestRoutePath  = "/api/client/conversations/{conversationId}/messages/{messageId}/react"
)

// React to a message in a conversation.
type ReactToMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to. This is typically a UUIDv7.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message to react to. This is typically a UUIDv7.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth ReactToMessageRequestAuthParams

	// Request body
	Body ReactToMessageRequestBody
}

type ReactToMessageRequestBody struct {

	// A reaction from the recipient of a message (e.g., "like", "love", "laugh", "sad", "angry", etc.). Emoji-Only field. Null to remove reaction.
	//
	// Optional
	//
	Reaction *string `json:"Reaction,omitempty"`
}

type ReactToMessageRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewReactToMessageRequestBody(data map[string]any) (ReactToMessageRequestBody, error) {
	var body ReactToMessageRequestBody

	valReaction, ok := data["Reaction"]
	if !ok {

		// skip, leave as zero value

	} else {

		valReactionTyped, ok := valReaction.(string)
		if !ok {
			return body, fmt.Errorf("field 'Reaction' has incorrect type")
		}

		body.Reaction = &valReactionTyped

	}

	return body, nil
}

// NewReactToMessageRequest creates a new ReactToMessageRequest from an http.Request and performs parameter parsing and validation.
func NewReactToMessageRequest(w http.ResponseWriter, r *http.Request) (req ReactToMessageRequest, err error) {

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
	var body ReactToMessageRequestBody
	body, err = NewReactToMessageRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type ReactToMessage200Response struct {
}

// Message reacted to successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessage200Response(w http.ResponseWriter, response ReactToMessage200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type ReactToMessage400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessage400Response(w http.ResponseWriter, response ReactToMessage400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type ReactToMessage401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessage401Response(w http.ResponseWriter, response ReactToMessage401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type ReactToMessage403Response struct {
}

// Forbidden. The authenticated user is not a participant in the conversation or is not a recipient of the message.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessage403Response(w http.ResponseWriter, response ReactToMessage403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type ReactToMessage404Response struct {
}

// Conversation or message not found or Message not in the conversation id specified.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessage404Response(w http.ResponseWriter, response ReactToMessage404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type ReactToMessage500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessage500Response(w http.ResponseWriter, response ReactToMessage500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
