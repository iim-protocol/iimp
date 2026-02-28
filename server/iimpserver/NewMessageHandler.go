package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	NewMessageRequestHTTPMethod = "POST"
	NewMessageRequestRoutePath  = "/api/client/conversations/{conversationId}/messages"
)

// Send a new message in a conversation.
type NewMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation to send the message in. This is typically a UUIDv7.
	//
	// Required
	ConversationId string

	// Authentication parameters
	Auth NewMessageRequestAuthParams

	// Request body
	Body NewMessageRequestBody
}

type NewMessageRequestBody struct {

	// An optional list of attachments to be included with the message. Each attachment can be a file, image, or other media type that is associated with the message. The server will store the attachments and deliver them to the recipients along with the message content.
	//
	// Optional
	//
	Attachments []string `json:"Attachments,omitempty"`

	// The content of the message to be sent in the conversation. The content should be encrypted using an AES key, and the AES key should be encrypted for each recipient using their respective public keys. The server will store the encrypted message content and the encrypted keys for each recipient, allowing the recipients to decrypt the AES key using their private keys and then use it to decrypt the message content.
	//
	// Required
	//
	MessageContent NewMessageRequestBodyMessageContent `json:"MessageContent"`
}

type NewMessageRequestBodyMessageContent struct {

	// The content of the message to be sent in the conversation. The content should be encrypted using an AES key, and the AES key should be encrypted for each recipient using their respective public keys. The server will store the encrypted message content and the encrypted keys for each recipient, allowing the recipients to decrypt the AES key using their private keys and then use it to decrypt the message content.
	//
	// Required
	//
	// Must be non-empty
	Content string `json:"Content"`

	// Encryption details for the recipients of the message.
	//
	// Required
	//
	// Must be non-empty
	EncryptionData []NewMessageRequestBodyMessageContentEncryptionDataItem `json:"EncryptionData"`

	// The nonce (or initialization vector) used in the AES encryption of the message content. This should be a unique value for each message encrypted with the same AES key to ensure security. The nonce is required for the decryption process, as it is used along with the AES key to decrypt the message content. The server will store the nonce along with the encrypted message content and deliver it to the recipients, allowing them to use it in the decryption process. The nonce should be generated securely (e.g., using a cryptographically secure random number generator) and should be of 12 bytes (96 bits) in length for AES-256-GCM encryption.
	//
	// Required
	//
	// Must be non-empty
	Nonce string `json:"Nonce"`

	// The timestamp when the message content was created. Format => ISO 8601 (e.g., "2024-06-01T12:00:00Z"). This field is included to provide context about when the message content was created, which can be useful for ordering messages and displaying timestamps in the client applications.
	//
	// Required
	//
	// Must be non-empty
	Timestamp string `json:"Timestamp"`
}

type NewMessageRequestBodyMessageContentEncryptionDataItem struct {

	// Encryption details for a recipient of the message.
	//
	// Required
	//
	Encryption NewMessageRequestBodyMessageContentEncryptionDataItemEncryption `json:"Encryption"`

	// User ID of the recipient of the message. (localpart@domain). This field is included to associate the encryption details with the specific recipient, allowing the server to deliver the correct encrypted key and nonce to each recipient along with the encrypted message content.
	//
	// Required
	//
	// Must be non-empty
	RecipientId string `json:"RecipientId"`
}

type NewMessageRequestBodyMessageContentEncryptionDataItemEncryption struct {

	// The AES key used to encrypt the message content, encrypted with the recipient's public key using an asymmetric encryption algorithm (X25519 + HKDF). The server will store this encrypted key and deliver it to the recipient along with the encrypted message content, allowing the recipient to decrypt the AES key using their private key and then use it to decrypt the message content.
	//
	// Required
	//
	// Must be non-empty
	EncryptedKey string `json:"EncryptedKey"`

	// The nonce used in the encryption of the AES key for this recipient. This should be a unique value for each encrypted key to ensure security. The server will store this nonce along with the encrypted key and deliver it to the recipient, allowing them to use it in the decryption process. The nonce should be generated securely (e.g., using a cryptographically secure random number generator) and should be of 12 bytes (96 bits) in length for AES-256-GCM encryption.
	//
	// Required
	//
	// Must be non-empty
	EncryptedKeyNonce string `json:"EncryptedKeyNonce"`

	// An ephemeral public key generated by the sender for this message, used in the encryption process (X25519).
	//
	// Required
	//
	// Must be non-empty
	EphemeralPublicKey string `json:"EphemeralPublicKey"`

	// The unique identifier of the public key that was used to encrypt the message for this recipient. This should correspond to a KeyId returned by the server when the client added their public keys.
	//
	// Required
	//
	// Must be non-empty
	KeyId string `json:"KeyId"`
}

type NewMessageRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewNewMessageRequestBody(data map[string]any) (NewMessageRequestBody, error) {
	var body NewMessageRequestBody

	valAttachments, ok := data["Attachments"]
	if !ok {

		// skip, leave as zero value

	} else {

		valAttachmentsSlice, ok := valAttachments.([]any)
		if !ok {
			return body, fmt.Errorf("field 'Attachments' has incorrect type")
		}

		valAttachmentsTyped := make([]string, 0, len(valAttachmentsSlice))

		for idx, item := range valAttachmentsSlice {
			itemTyped, ok := item.(string)
			if !ok {
				return body, fmt.Errorf("element %d of field 'Attachments' has incorrect type", idx)
			}

			itemTyped = strings.TrimSpace(itemTyped)
			if itemTyped == "" {
				return body, fmt.Errorf("element %d of field 'Attachments' must be non-empty", idx)
			}

			valAttachmentsTyped = append(valAttachmentsTyped, itemTyped)
		}

		body.Attachments = valAttachmentsTyped

	}

	valMessageContent, ok := data["MessageContent"]
	if !ok {

		return body, fmt.Errorf("missing required field 'MessageContent'")

	} else {

		valMessageContentTypedMap, ok := valMessageContent.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'MessageContent' has incorrect type")
		}
		valMessageContentTyped, err := NewNewMessageRequestBodyMessageContent(valMessageContentTypedMap)
		if err != nil {
			return body, fmt.Errorf("field 'MessageContent' is invalid: %w", err)
		}

		body.MessageContent = valMessageContentTyped

	}

	return body, nil
}

func NewNewMessageRequestBodyMessageContent(data map[string]any) (NewMessageRequestBodyMessageContent, error) {
	var body NewMessageRequestBodyMessageContent

	valContent, ok := data["Content"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Content'")

	} else {

		valContentTyped, ok := valContent.(string)
		if !ok {
			return body, fmt.Errorf("field 'Content' has incorrect type")
		}

		valContentTyped = strings.TrimSpace(valContentTyped)
		if len(valContentTyped) == 0 {
			return body, fmt.Errorf("field 'Content' must be non-empty")
		}

		body.Content = valContentTyped

	}

	valEncryptionData, ok := data["EncryptionData"]
	if !ok {

		return body, fmt.Errorf("missing required field 'EncryptionData'")

	} else {

		valEncryptionDataSlice, ok := valEncryptionData.([]any)
		if !ok {
			return body, fmt.Errorf("field 'EncryptionData' has incorrect type")
		}

		if len(valEncryptionDataSlice) == 0 {
			return body, fmt.Errorf("field 'EncryptionData' must be non-empty")
		}

		valEncryptionDataTyped := make([]NewMessageRequestBodyMessageContentEncryptionDataItem, 0, len(valEncryptionDataSlice))

		for idx, item := range valEncryptionDataSlice {
			itemMap, ok := item.(map[string]any)
			if !ok {
				return body, fmt.Errorf("element %d of field 'EncryptionData' has incorrect type", idx)
			}
			validatedItem, err := NewNewMessageRequestBodyMessageContentEncryptionDataItem(itemMap)
			if err != nil {
				return body, fmt.Errorf("element %d of field 'EncryptionData' is invalid: %w", idx, err)
			}
			valEncryptionDataTyped = append(valEncryptionDataTyped, validatedItem)
		}

		body.EncryptionData = valEncryptionDataTyped

	}

	valNonce, ok := data["Nonce"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Nonce'")

	} else {

		valNonceTyped, ok := valNonce.(string)
		if !ok {
			return body, fmt.Errorf("field 'Nonce' has incorrect type")
		}

		valNonceTyped = strings.TrimSpace(valNonceTyped)
		if len(valNonceTyped) == 0 {
			return body, fmt.Errorf("field 'Nonce' must be non-empty")
		}

		body.Nonce = valNonceTyped

	}

	valTimestamp, ok := data["Timestamp"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Timestamp'")

	} else {

		valTimestampTyped, ok := valTimestamp.(string)
		if !ok {
			return body, fmt.Errorf("field 'Timestamp' has incorrect type")
		}

		valTimestampTyped = strings.TrimSpace(valTimestampTyped)
		if len(valTimestampTyped) == 0 {
			return body, fmt.Errorf("field 'Timestamp' must be non-empty")
		}

		body.Timestamp = valTimestampTyped

	}

	return body, nil
}

func NewNewMessageRequestBodyMessageContentEncryptionDataItem(data map[string]any) (NewMessageRequestBodyMessageContentEncryptionDataItem, error) {
	var body NewMessageRequestBodyMessageContentEncryptionDataItem

	valEncryption, ok := data["Encryption"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Encryption'")

	} else {

		valEncryptionTypedMap, ok := valEncryption.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'Encryption' has incorrect type")
		}
		valEncryptionTyped, err := NewNewMessageRequestBodyMessageContentEncryptionDataItemEncryption(valEncryptionTypedMap)
		if err != nil {
			return body, fmt.Errorf("field 'Encryption' is invalid: %w", err)
		}

		body.Encryption = valEncryptionTyped

	}

	valRecipientId, ok := data["RecipientId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'RecipientId'")

	} else {

		valRecipientIdTyped, ok := valRecipientId.(string)
		if !ok {
			return body, fmt.Errorf("field 'RecipientId' has incorrect type")
		}

		valRecipientIdTyped = strings.TrimSpace(valRecipientIdTyped)
		if len(valRecipientIdTyped) == 0 {
			return body, fmt.Errorf("field 'RecipientId' must be non-empty")
		}

		body.RecipientId = valRecipientIdTyped

	}

	return body, nil
}

func NewNewMessageRequestBodyMessageContentEncryptionDataItemEncryption(data map[string]any) (NewMessageRequestBodyMessageContentEncryptionDataItemEncryption, error) {
	var body NewMessageRequestBodyMessageContentEncryptionDataItemEncryption

	valEncryptedKey, ok := data["EncryptedKey"]
	if !ok {

		return body, fmt.Errorf("missing required field 'EncryptedKey'")

	} else {

		valEncryptedKeyTyped, ok := valEncryptedKey.(string)
		if !ok {
			return body, fmt.Errorf("field 'EncryptedKey' has incorrect type")
		}

		valEncryptedKeyTyped = strings.TrimSpace(valEncryptedKeyTyped)
		if len(valEncryptedKeyTyped) == 0 {
			return body, fmt.Errorf("field 'EncryptedKey' must be non-empty")
		}

		body.EncryptedKey = valEncryptedKeyTyped

	}

	valEncryptedKeyNonce, ok := data["EncryptedKeyNonce"]
	if !ok {

		return body, fmt.Errorf("missing required field 'EncryptedKeyNonce'")

	} else {

		valEncryptedKeyNonceTyped, ok := valEncryptedKeyNonce.(string)
		if !ok {
			return body, fmt.Errorf("field 'EncryptedKeyNonce' has incorrect type")
		}

		valEncryptedKeyNonceTyped = strings.TrimSpace(valEncryptedKeyNonceTyped)
		if len(valEncryptedKeyNonceTyped) == 0 {
			return body, fmt.Errorf("field 'EncryptedKeyNonce' must be non-empty")
		}

		body.EncryptedKeyNonce = valEncryptedKeyNonceTyped

	}

	valEphemeralPublicKey, ok := data["EphemeralPublicKey"]
	if !ok {

		return body, fmt.Errorf("missing required field 'EphemeralPublicKey'")

	} else {

		valEphemeralPublicKeyTyped, ok := valEphemeralPublicKey.(string)
		if !ok {
			return body, fmt.Errorf("field 'EphemeralPublicKey' has incorrect type")
		}

		valEphemeralPublicKeyTyped = strings.TrimSpace(valEphemeralPublicKeyTyped)
		if len(valEphemeralPublicKeyTyped) == 0 {
			return body, fmt.Errorf("field 'EphemeralPublicKey' must be non-empty")
		}

		body.EphemeralPublicKey = valEphemeralPublicKeyTyped

	}

	valKeyId, ok := data["KeyId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'KeyId'")

	} else {

		valKeyIdTyped, ok := valKeyId.(string)
		if !ok {
			return body, fmt.Errorf("field 'KeyId' has incorrect type")
		}

		valKeyIdTyped = strings.TrimSpace(valKeyIdTyped)
		if len(valKeyIdTyped) == 0 {
			return body, fmt.Errorf("field 'KeyId' must be non-empty")
		}

		body.KeyId = valKeyIdTyped

	}

	return body, nil
}

// NewNewMessageRequest creates a new NewMessageRequest from an http.Request and performs parameter parsing and validation.
func NewNewMessageRequest(w http.ResponseWriter, r *http.Request) (req NewMessageRequest, err error) {

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

	bodyData := make(map[string]any)

	maxBodyBytes := int64(256 << 10) // 256 KB default limit

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err = json.NewDecoder(r.Body).Decode(&bodyData)
	if err != nil {
		return
	}
	var body NewMessageRequestBody
	body, err = NewNewMessageRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type NewMessage201Response struct {

	// Response body
	Body NewMessage201ResponseBody
}

type NewMessage201ResponseBody struct {

	// A unique identifier for the message, typically a UUIDv7.
	//
	// Required
	//
	// Must be non-empty
	MessageId string `json:"MessageId"`
}

// Message sent successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewMessage201Response(w http.ResponseWriter, response NewMessage201Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(201)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type NewMessage400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewMessage400Response(w http.ResponseWriter, response NewMessage400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type NewMessage401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewMessage401Response(w http.ResponseWriter, response NewMessage401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type NewMessage403Response struct {
}

// Forbidden. The authenticated user is not a participant in the conversation.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewMessage403Response(w http.ResponseWriter, response NewMessage403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type NewMessage404Response struct {
}

// Conversation not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewMessage404Response(w http.ResponseWriter, response NewMessage404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type NewMessage500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewMessage500Response(w http.ResponseWriter, response NewMessage500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
