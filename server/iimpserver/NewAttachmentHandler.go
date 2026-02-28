package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	NewAttachmentRequestHTTPMethod = "POST"
	NewAttachmentRequestRoutePath  = "/api/client/attachments"
)

// Upload an attachment to be included with a message.
type NewAttachmentRequest struct {

	// Authentication parameters
	Auth NewAttachmentRequestAuthParams

	// Request body
	Body NewAttachmentRequestBody
}

type NewAttachmentRequestBody struct {

	// The MIME type of the attachment (e.g., "image/png", "application/pdf", etc.).
	//
	// Required
	//
	// Must be non-empty
	ContentType string `json:"ContentType"`

	// The original filename of the attachment.
	//
	// Required
	//
	// Must be non-empty
	Filename string `json:"Filename"`

	// The size of the attachment in bytes. The server may enforce a maximum attachment size.
	//
	// Required
	//
	Size float64 `json:"Size"`
}

type NewAttachmentRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewNewAttachmentRequestBody(data map[string]any) (NewAttachmentRequestBody, error) {
	var body NewAttachmentRequestBody

	valContentType, ok := data["ContentType"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ContentType'")

	} else {

		valContentTypeTyped, ok := valContentType.(string)
		if !ok {
			return body, fmt.Errorf("field 'ContentType' has incorrect type")
		}

		valContentTypeTyped = strings.TrimSpace(valContentTypeTyped)
		if len(valContentTypeTyped) == 0 {
			return body, fmt.Errorf("field 'ContentType' must be non-empty")
		}

		body.ContentType = valContentTypeTyped

	}

	valFilename, ok := data["Filename"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Filename'")

	} else {

		valFilenameTyped, ok := valFilename.(string)
		if !ok {
			return body, fmt.Errorf("field 'Filename' has incorrect type")
		}

		valFilenameTyped = strings.TrimSpace(valFilenameTyped)
		if len(valFilenameTyped) == 0 {
			return body, fmt.Errorf("field 'Filename' must be non-empty")
		}

		body.Filename = valFilenameTyped

	}

	valSize, ok := data["Size"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Size'")

	} else {

		valSizeTyped, ok := valSize.(float64)
		if !ok {
			return body, fmt.Errorf("field 'Size' has incorrect type")
		}

		body.Size = valSizeTyped

	}

	return body, nil
}

// NewNewAttachmentRequest creates a new NewAttachmentRequest from an http.Request and performs parameter parsing and validation.
func NewNewAttachmentRequest(w http.ResponseWriter, r *http.Request) (req NewAttachmentRequest, err error) {

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
	var body NewAttachmentRequestBody
	body, err = NewNewAttachmentRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type NewAttachment201Response struct {

	// Response body
	Body NewAttachment201ResponseBody
}

type NewAttachment201ResponseBody struct {

	// A unique identifier for the attachment, typically a UUIDv7. This ID can be used to reference the attachment in future operations, such as including it in a message payload when sending a message with attachments. The server will store the attachment and deliver it to the recipients along with the message content.
	//
	// Required
	//
	// Must be non-empty
	AttachmentId string `json:"AttachmentId"`
}

// Attachment uploaded successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewAttachment201Response(w http.ResponseWriter, response NewAttachment201Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(201)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type NewAttachment400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewAttachment400Response(w http.ResponseWriter, response NewAttachment400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type NewAttachment401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewAttachment401Response(w http.ResponseWriter, response NewAttachment401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type NewAttachment413Response struct {
}

// Payload too large. The specified size exceeds the allowed maximum attachment size. This size limit is set by the protocol at 1000MB.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewAttachment413Response(w http.ResponseWriter, response NewAttachment413Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(413)
	return nil

}

type NewAttachment500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewAttachment500Response(w http.ResponseWriter, response NewAttachment500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
