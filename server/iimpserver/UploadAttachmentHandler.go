package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	UploadAttachmentRequestHTTPMethod = "PUT"
	UploadAttachmentRequestRoutePath  = "/api/client/attachments/{attachmentId}/bytes"
)

// Upload the bytes of an attachment. The bytes go in the request body.
type UploadAttachmentRequest struct {

	// Source: path parameter "{attachmentId}"
	//

	// Required
	AttachmentId string

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

type UploadAttachment204Response struct {
}

// Attachment uploaded successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment204Response(w http.ResponseWriter, response UploadAttachment204Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(204)
	return nil

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

type UploadAttachment409Response struct {
}

// Conflict. The attachment bytes have already been uploaded for the specified AttachmentId.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment409Response(w http.ResponseWriter, response UploadAttachment409Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(409)
	return nil

}

type UploadAttachment413Response struct {

	// Response body
	Body UploadAttachment413ResponseBody
}

type UploadAttachment413ResponseBody struct {

	// The total size of the attachment specified during creation in bytes.
	//
	// Required
	//
	AttachmentSize float64 `json:"AttachmentSize"`
}

// Payload too large. The upload exceeds the allowed size for the attachment OR the attachment is too large (This size limit is set by the protocol at 1000MB).
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUploadAttachment413Response(w http.ResponseWriter, response UploadAttachment413Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(413)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

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
