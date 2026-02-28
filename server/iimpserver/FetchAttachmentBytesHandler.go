package iimpserver

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	FetchAttachmentBytesRequestHTTPMethod = "GET"
	FetchAttachmentBytesRequestRoutePath  = "/api/client/conversations/{conversationId}/messages/{messageId}/attachments/{attachmentId}/bytes"
)

// Fetch the bytes of an attachment for a message in a conversation. This is a NOOP endpoint for documentation, since the actual fetching of the attachment bytes is to be done by the client.
type FetchAttachmentBytesRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to. This is typically a UUIDv7.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message that the attachment belongs to. This is typically a UUIDv7.
	//
	// Required
	MessageId string

	// Source: path parameter "{attachmentId}"
	//

	// The unique identifier of the attachment to fetch. This is typically a UUIDv7 and should correspond to an attachment that was previously uploaded to the server using the NewAttachment endpoint.
	//
	// Required
	AttachmentId string

	// Authentication parameters
	Auth FetchAttachmentBytesRequestAuthParams
}

type FetchAttachmentBytesRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

// NewFetchAttachmentBytesRequest creates a new FetchAttachmentBytesRequest from an http.Request and performs parameter parsing and validation.
func NewFetchAttachmentBytesRequest(w http.ResponseWriter, r *http.Request) (req FetchAttachmentBytesRequest, err error) {

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

	valAttachmentId, err := parsestringParam(r.PathValue("attachmentId"), "path: attachmentId", true)
	if err != nil {
		return
	}

	req.AttachmentId = *valAttachmentId

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

type FetchAttachmentBytes200Response struct {
}

// Attachment bytes fetched successfully. The response body will contain the raw bytes of the attachment, and the Content-Type header will indicate the MIME type of the attachment (e.g., "image/png", "application/pdf", etc.). The client can use this information to handle the attachment appropriately (e.g., display an image, prompt for download, etc.).
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytes200Response(w http.ResponseWriter, response FetchAttachmentBytes200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type FetchAttachmentBytes400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytes400Response(w http.ResponseWriter, response FetchAttachmentBytes400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type FetchAttachmentBytes401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytes401Response(w http.ResponseWriter, response FetchAttachmentBytes401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type FetchAttachmentBytes403Response struct {
}

// Forbidden. The authenticated user is not a participant in the conversation or is not a recipient of the message or is not allowed to access the attachment.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytes403Response(w http.ResponseWriter, response FetchAttachmentBytes403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type FetchAttachmentBytes404Response struct {
}

// Conversation, message, or attachment not found or Attachment not in the message id or conversation id specified.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytes404Response(w http.ResponseWriter, response FetchAttachmentBytes404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type FetchAttachmentBytes500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteFetchAttachmentBytes500Response(w http.ResponseWriter, response FetchAttachmentBytes500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
