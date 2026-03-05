package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	UploadAttachmentRequestHTTPMethod = "POST"
	UploadAttachmentRequestRoutePath  = "/iimp/api/client/attachments"
)

// Upload the bytes of an attachment. The bytes go in the request body.
type UploadAttachmentRequest struct {

	// Source: header parameter "X-IIMP-Attachment-Filename"
	//

	// The original filename of the attachment.
	//
	// Required
	Filename string

	// Authentication parameters
	Auth UploadAttachmentRequestAuthParams
}

type UploadAttachmentRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

// NewUploadAttachmentRequest creates a new UploadAttachmentRequest from an http.Request and performs parameter parsing and validation.
func NewUploadAttachmentRequest(w http.ResponseWriter, r *http.Request) (req UploadAttachmentRequest, err error) {

	valFilename, err := parsestringParam(r.Header.Get("X-IIMP-Attachment-Filename"), "header: X-IIMP-Attachment-Filename", true)
	if err != nil {
		return
	}

	req.Filename = *valFilename

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

type UploadAttachment201Response struct {

	// Response body
	Body UploadAttachment201ResponseBody
}

type UploadAttachment201ResponseBody struct {

	// A unique identifier for the file, which should be added to the new message payload to reference the file in messages.
	//
	// Required
	//
	// Must be non-empty
	FileId string `json:"FileId"`
}

// Attachment uploaded successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment201Response(w http.ResponseWriter, response UploadAttachment201Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(201)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type UploadAttachment400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment400Response(w http.ResponseWriter, response UploadAttachment400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type UploadAttachment401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment401Response(w http.ResponseWriter, response UploadAttachment401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type UploadAttachment403Response struct {
}

// Forbidden. The authenticated user is not allowed to upload the attachment.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment403Response(w http.ResponseWriter, response UploadAttachment403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type UploadAttachment404Response struct {
}

// Attachment not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment404Response(w http.ResponseWriter, response UploadAttachment404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type UploadAttachment413Response struct {
}

// Payload too large. The specified size exceeds the allowed maximum attachment size. This size limit is set by the protocol at 1000MB.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment413Response(w http.ResponseWriter, response UploadAttachment413Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(413)
	return nil

}

type UploadAttachment500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment500Response(w http.ResponseWriter, response UploadAttachment500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
