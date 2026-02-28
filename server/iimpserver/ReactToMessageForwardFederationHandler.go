package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	ReactToMessageForwardFederationRequestHTTPMethod = "POST"
	ReactToMessageForwardFederationRequestRoutePath  = "/api/federation/conversations/{conversationId}/messages/{messageId}/react/forward"
)

// \"FEDERATION\" React to a message in a conversation on another server.
type ReactToMessageForwardFederationRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// Unique identifier of the conversation to react to the message in.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// Unique identifier of the message to react to.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth ReactToMessageForwardFederationRequestAuthParams

	// Request body
	Body ReactToMessageForwardFederationRequestBody
}

type ReactToMessageForwardFederationRequestBody struct {

	// Original received reaction on the requesting server.
	//
	// Optional
	//
	OriginalReaction *ReactToMessageForwardFederationRequestBodyOriginalReaction `json:"OriginalReaction,omitempty"`

	// User ID of the user who made the reaction. This should be in the format localpart@domain and must belong to the requesting server.
	//
	// Required
	//
	// Must be non-empty
	ReactingUserId string `json:"ReactingUserId"`
}

type ReactToMessageForwardFederationRequestBodyOriginalReaction struct {

	// A reaction from the recipient of a message (e.g., "like", "love", "laugh", "sad", "angry", etc.). Emoji-Only field. Null to remove reaction.
	//
	// Optional
	//
	Reaction *string `json:"Reaction,omitempty"`
}

type ReactToMessageForwardFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewReactToMessageForwardFederationRequestBody(data map[string]any) (ReactToMessageForwardFederationRequestBody, error) {
	var body ReactToMessageForwardFederationRequestBody

	valOriginalReaction, ok := data["OriginalReaction"]
	if !ok {

		// skip, leave as zero value

	} else {

		valOriginalReactionTypedMap, ok := valOriginalReaction.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'OriginalReaction' has incorrect type")
		}
		valOriginalReactionTyped, err := NewReactToMessageForwardFederationRequestBodyOriginalReaction(valOriginalReactionTypedMap)
		if err != nil {
			return body, fmt.Errorf("field 'OriginalReaction' is invalid: %w", err)
		}

		body.OriginalReaction = &valOriginalReactionTyped

	}

	valReactingUserId, ok := data["ReactingUserId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ReactingUserId'")

	} else {

		valReactingUserIdTyped, ok := valReactingUserId.(string)
		if !ok {
			return body, fmt.Errorf("field 'ReactingUserId' has incorrect type")
		}

		valReactingUserIdTyped = strings.TrimSpace(valReactingUserIdTyped)
		if len(valReactingUserIdTyped) == 0 {
			return body, fmt.Errorf("field 'ReactingUserId' must be non-empty")
		}

		body.ReactingUserId = valReactingUserIdTyped

	}

	return body, nil
}

func NewReactToMessageForwardFederationRequestBodyOriginalReaction(data map[string]any) (ReactToMessageForwardFederationRequestBodyOriginalReaction, error) {
	var body ReactToMessageForwardFederationRequestBodyOriginalReaction

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

// NewReactToMessageForwardFederationRequest creates a new ReactToMessageForwardFederationRequest from an http.Request and performs parameter parsing and validation.
func NewReactToMessageForwardFederationRequest(w http.ResponseWriter, r *http.Request) (req ReactToMessageForwardFederationRequest, err error) {

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
	var body ReactToMessageForwardFederationRequestBody
	body, err = NewReactToMessageForwardFederationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type ReactToMessageForwardFederation200Response struct {
}

// Message reacted to successfully from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessageForwardFederation200Response(w http.ResponseWriter, response ReactToMessageForwardFederation200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type ReactToMessageForwardFederation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessageForwardFederation400Response(w http.ResponseWriter, response ReactToMessageForwardFederation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type ReactToMessageForwardFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessageForwardFederation401Response(w http.ResponseWriter, response ReactToMessageForwardFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type ReactToMessageForwardFederation403Response struct {
}

// Forbidden. Requesting server's JWT is not valid (JWT iss domain != ReactingUserId domain) or ReactingUserId does not belong to the requesting server, OR the receiving server is not the conversation owner's server.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessageForwardFederation403Response(w http.ResponseWriter, response ReactToMessageForwardFederation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type ReactToMessageForwardFederation404Response struct {
}

// Conversation or message not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessageForwardFederation404Response(w http.ResponseWriter, response ReactToMessageForwardFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type ReactToMessageForwardFederation500Response struct {
}

// Internal server error while reacting to the message from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteReactToMessageForwardFederation500Response(w http.ResponseWriter, response ReactToMessageForwardFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
