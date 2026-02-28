package iimpserver

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	FetchAttachmentBytesFederationRequestHTTPMethod = "GET"
	FetchAttachmentBytesFederationRequestRoutePath  = "/api/federation/conversations/{conversationId}/messages/{messageId}/attachments/{attachmentId}/bytes"
)

// \"FEDERATION\" Fetch the bytes of an attachment from another server. This is a noop endpoint for documentation purposes, the server should implement fetching the actual bytes using the provided endpoint. Server must implement this, requesting server needs to fetch the bytes NOT using the SDK.
type FetchAttachmentBytesFederationRequest struct {

	// Source: path parameter "{attachmentId}"
	//

	// Unique identifier of the attachment to fetch.
	//
	// Required
	AttachmentId string

	// Source: path parameter "{messageId}"
	//

	// Unique identifier of the message that the attachment belongs to.
	//
	// Required
	MessageId string

	// Source: path parameter "{conversationId}"
	//

	// Unique identifier of the conversation that the message belongs to.
	//
	// Required
	ConversationId string

	// Authentication parameters
	Auth FetchAttachmentBytesFederationRequestAuthParams
}

type FetchAttachmentBytesFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

// NewFetchAttachmentBytesFederationRequest creates a new FetchAttachmentBytesFederationRequest from an http.Request and performs parameter parsing and validation.
func NewFetchAttachmentBytesFederationRequest(w http.ResponseWriter, r *http.Request) (req FetchAttachmentBytesFederationRequest, err error) {

	valAttachmentId, err := parsestringParam(r.PathValue("attachmentId"), "path: attachmentId", true)
	if err != nil {
		return
	}

	req.AttachmentId = *valAttachmentId

	valMessageId, err := parsestringParam(r.PathValue("messageId"), "path: messageId", true)
	if err != nil {
		return
	}

	req.MessageId = *valMessageId

	valConversationId, err := parsestringParam(r.PathValue("conversationId"), "path: conversationId", true)
	if err != nil {
		return
	}

	req.ConversationId = *valConversationId

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

type FetchAttachmentBytesFederation200Response struct {
}

// Attachment bytes fetched successfully from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytesFederation200Response(w http.ResponseWriter, response FetchAttachmentBytesFederation200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type FetchAttachmentBytesFederation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytesFederation400Response(w http.ResponseWriter, response FetchAttachmentBytesFederation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type FetchAttachmentBytesFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytesFederation401Response(w http.ResponseWriter, response FetchAttachmentBytesFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type FetchAttachmentBytesFederation403Response struct {
}

// Forbidden. The requesting server is not allowed to access the attachment.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytesFederation403Response(w http.ResponseWriter, response FetchAttachmentBytesFederation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type FetchAttachmentBytesFederation404Response struct {
}

// Conversation, message, or attachment not found, or the attachment does not belong to the message or the message does not belong to the conversation specified in the path parameters.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytesFederation404Response(w http.ResponseWriter, response FetchAttachmentBytesFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type FetchAttachmentBytesFederation500Response struct {
}

// Internal server error while fetching the attachment bytes from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytesFederation500Response(w http.ResponseWriter, response FetchAttachmentBytesFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
