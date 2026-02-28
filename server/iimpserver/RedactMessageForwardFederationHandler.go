package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	RedactMessageForwardFederationRequestHTTPMethod = "POST"
	RedactMessageForwardFederationRequestRoutePath  = "/api/federation/conversations/{conversationId}/messages/{messageId}/redact/forward"
)

// \"FEDERATION\" Redact a message in a conversation on another server.
type RedactMessageForwardFederationRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// Unique identifier of the conversation to redact the message in.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// Unique identifier of the message to redact.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth RedactMessageForwardFederationRequestAuthParams

	// Request body
	Body RedactMessageForwardFederationRequestBody
}

type RedactMessageForwardFederationRequestBody struct {

	// User ID of the sender of the message to redact. This should be in the format localpart@domain and must belong to the requesting server and should be equal to the sender's id on the receiving server's message.
	//
	// Required
	//
	// Must be non-empty
	SenderUserId string `json:"SenderUserId"`
}

type RedactMessageForwardFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewRedactMessageForwardFederationRequestBody(data map[string]any) (RedactMessageForwardFederationRequestBody, error) {
	var body RedactMessageForwardFederationRequestBody

	valSenderUserId, ok := data["SenderUserId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'SenderUserId'")

	} else {

		valSenderUserIdTyped, ok := valSenderUserId.(string)
		if !ok {
			return body, fmt.Errorf("field 'SenderUserId' has incorrect type")
		}

		valSenderUserIdTyped = strings.TrimSpace(valSenderUserIdTyped)
		if len(valSenderUserIdTyped) == 0 {
			return body, fmt.Errorf("field 'SenderUserId' must be non-empty")
		}

		body.SenderUserId = valSenderUserIdTyped

	}

	return body, nil
}

// NewRedactMessageForwardFederationRequest creates a new RedactMessageForwardFederationRequest from an http.Request and performs parameter parsing and validation.
func NewRedactMessageForwardFederationRequest(w http.ResponseWriter, r *http.Request) (req RedactMessageForwardFederationRequest, err error) {

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
	var body RedactMessageForwardFederationRequestBody
	body, err = NewRedactMessageForwardFederationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type RedactMessageForwardFederation200Response struct {
}

// Message redacted successfully from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessageForwardFederation200Response(w http.ResponseWriter, response RedactMessageForwardFederation200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type RedactMessageForwardFederation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessageForwardFederation400Response(w http.ResponseWriter, response RedactMessageForwardFederation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type RedactMessageForwardFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessageForwardFederation401Response(w http.ResponseWriter, response RedactMessageForwardFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type RedactMessageForwardFederation403Response struct {
}

// Forbidden. Requesting server's JWT is not valid (JWT iss domain != sender id domain), or user does not have permission to redact the message, or Receiving server is not conversation owner's server.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessageForwardFederation403Response(w http.ResponseWriter, response RedactMessageForwardFederation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type RedactMessageForwardFederation404Response struct {
}

// Conversation or message not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessageForwardFederation404Response(w http.ResponseWriter, response RedactMessageForwardFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type RedactMessageForwardFederation500Response struct {
}

// Internal server error while redacting the message from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteRedactMessageForwardFederation500Response(w http.ResponseWriter, response RedactMessageForwardFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
