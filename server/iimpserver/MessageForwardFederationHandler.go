package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	MessageForwardFederationRequestHTTPMethod = "POST"
	MessageForwardFederationRequestRoutePath  = "/api/federation/conversations/{conversationId}/messages/forward"
)

// \"FEDERATION\" Forward an existing message to a conversation from another server.
type MessageForwardFederationRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// Unique identifier of the conversation to forward the message to.
	//
	// Required
	ConversationId string

	// Authentication parameters
	Auth MessageForwardFederationRequestAuthParams

	// Request body
	Body MessageForwardFederationRequestBody
}

type MessageForwardFederationRequestBody struct {

	// Message details.
	//
	// Required
	//
	OriginalMessageRequest MessageForwardFederationRequestBodyOriginalMessageRequest `json:"OriginalMessageRequest"`

	// User ID of the sender of the forwarded message. This should be in the format localpart@domain and must belong to the requesting server.
	//
	// Required
	//
	// Must be non-empty
	SenderUserId string `json:"SenderUserId"`
}

type MessageForwardFederationRequestBodyOriginalMessageRequest struct {

	// An optional list of attachments to be included with the message. Each attachment can be a file, image, or other media type that is associated with the message. The server will store the attachments and deliver them to the recipients along with the message content.
	//
	// Optional
	//
	Attachments []string `json:"Attachments,omitempty"`

	// The content of the message to be sent in the conversation. The content should be encrypted using an AES key, and the AES key should be encrypted for each recipient using their respective public keys. The server will store the encrypted message content and the encrypted keys for each recipient, allowing the recipients to decrypt the AES key using their private keys and then use it to decrypt the message content.
	//
	// Required
	//
	MessageContent MessageForwardFederationRequestBodyOriginalMessageRequestMessageContent `json:"MessageContent"`
}

type MessageForwardFederationRequestBodyOriginalMessageRequestMessageContent struct {

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
	EncryptionData []MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItem `json:"EncryptionData"`

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

type MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItem struct {

	// Encryption details for a recipient of the message.
	//
	// Required
	//
	Encryption MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItemEncryption `json:"Encryption"`

	// User ID of the recipient of the message. (localpart@domain). This field is included to associate the encryption details with the specific recipient, allowing the server to deliver the correct encrypted key and nonce to each recipient along with the encrypted message content.
	//
	// Required
	//
	// Must be non-empty
	RecipientId string `json:"RecipientId"`
}

type MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItemEncryption struct {

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

type MessageForwardFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewMessageForwardFederationRequestBody(data map[string]any) (MessageForwardFederationRequestBody, error) {
	var body MessageForwardFederationRequestBody

	valOriginalMessageRequest, ok := data["OriginalMessageRequest"]
	if !ok {

		return body, fmt.Errorf("missing required field 'OriginalMessageRequest'")

	} else {

		valOriginalMessageRequestTypedMap, ok := valOriginalMessageRequest.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'OriginalMessageRequest' has incorrect type")
		}
		valOriginalMessageRequestTyped, err := NewMessageForwardFederationRequestBodyOriginalMessageRequest(valOriginalMessageRequestTypedMap)
		if err != nil {
			return body, fmt.Errorf("field 'OriginalMessageRequest' is invalid: %w", err)
		}

		body.OriginalMessageRequest = valOriginalMessageRequestTyped

	}

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

func NewMessageForwardFederationRequestBodyOriginalMessageRequest(data map[string]any) (MessageForwardFederationRequestBodyOriginalMessageRequest, error) {
	var body MessageForwardFederationRequestBodyOriginalMessageRequest

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
		valMessageContentTyped, err := NewMessageForwardFederationRequestBodyOriginalMessageRequestMessageContent(valMessageContentTypedMap)
		if err != nil {
			return body, fmt.Errorf("field 'MessageContent' is invalid: %w", err)
		}

		body.MessageContent = valMessageContentTyped

	}

	return body, nil
}

func NewMessageForwardFederationRequestBodyOriginalMessageRequestMessageContent(data map[string]any) (MessageForwardFederationRequestBodyOriginalMessageRequestMessageContent, error) {
	var body MessageForwardFederationRequestBodyOriginalMessageRequestMessageContent

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

		valEncryptionDataTyped := make([]MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItem, 0, len(valEncryptionDataSlice))

		for idx, item := range valEncryptionDataSlice {
			itemMap, ok := item.(map[string]any)
			if !ok {
				return body, fmt.Errorf("element %d of field 'EncryptionData' has incorrect type", idx)
			}
			validatedItem, err := NewMessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItem(itemMap)
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

func NewMessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItem(data map[string]any) (MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItem, error) {
	var body MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItem

	valEncryption, ok := data["Encryption"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Encryption'")

	} else {

		valEncryptionTypedMap, ok := valEncryption.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'Encryption' has incorrect type")
		}
		valEncryptionTyped, err := NewMessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItemEncryption(valEncryptionTypedMap)
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

func NewMessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItemEncryption(data map[string]any) (MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItemEncryption, error) {
	var body MessageForwardFederationRequestBodyOriginalMessageRequestMessageContentEncryptionDataItemEncryption

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

// NewMessageForwardFederationRequest creates a new MessageForwardFederationRequest from an http.Request and performs parameter parsing and validation.
func NewMessageForwardFederationRequest(w http.ResponseWriter, r *http.Request) (req MessageForwardFederationRequest, err error) {

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
	var body MessageForwardFederationRequestBody
	body, err = NewMessageForwardFederationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type MessageForwardFederation200Response struct {
}

// Message forwarded successfully from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageForwardFederation200Response(w http.ResponseWriter, response MessageForwardFederation200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type MessageForwardFederation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageForwardFederation400Response(w http.ResponseWriter, response MessageForwardFederation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type MessageForwardFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageForwardFederation401Response(w http.ResponseWriter, response MessageForwardFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type MessageForwardFederation403Response struct {
}

// Forbidden. Requesting server's JWT is not valid (JWT iss domain != SenderUserId domain) or SenderUserId does not belong to the requesting server, OR the receiving server is not the conversation owner's server.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageForwardFederation403Response(w http.ResponseWriter, response MessageForwardFederation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type MessageForwardFederation404Response struct {
}

// Conversation not found or Sender User Id not a participant.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageForwardFederation404Response(w http.ResponseWriter, response MessageForwardFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type MessageForwardFederation500Response struct {
}

// Internal server error while forwarding the message from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageForwardFederation500Response(w http.ResponseWriter, response MessageForwardFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
