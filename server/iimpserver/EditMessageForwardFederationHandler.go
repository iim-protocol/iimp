package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	EditMessageForwardFederationRequestHTTPMethod = "PUT"
	EditMessageForwardFederationRequestRoutePath  = "/api/federation/conversations/{conversationId}/messages/{messageId}/edit/forward"
)

// \"FEDERATION\" Edit a message in a conversation on another server.
type EditMessageForwardFederationRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// Unique identifier of the conversation to edit the message in.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// Unique identifier of the message to edit.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth EditMessageForwardFederationRequestAuthParams

	// Request body
	Body EditMessageForwardFederationRequestBody
}

type EditMessageForwardFederationRequestBody struct {

	// User ID of the sender of the message to edit. This should be in the format localpart@domain and must belong to the requesting server and should be equal to the sender's id on the receiving server's message.
	//
	// Required
	//
	// Must be non-empty
	SenderUserId string `json:"SenderUserId"`

	// Updated message details.
	//
	// Required
	//
	UpdatedMessage EditMessageForwardFederationRequestBodyUpdatedMessage `json:"UpdatedMessage"`
}

type EditMessageForwardFederationRequestBodyUpdatedMessage struct {

	// Required
	//
	MessageContent EditMessageForwardFederationRequestBodyUpdatedMessageMessageContent `json:"MessageContent"`
}

type EditMessageForwardFederationRequestBodyUpdatedMessageMessageContent struct {

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
	EncryptionData []EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItem `json:"EncryptionData"`

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

type EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItem struct {

	// Encryption details for a recipient of the message.
	//
	// Required
	//
	Encryption EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItemEncryption `json:"Encryption"`

	// User ID of the recipient of the message. (localpart@domain). This field is included to associate the encryption details with the specific recipient, allowing the server to deliver the correct encrypted key and nonce to each recipient along with the encrypted message content.
	//
	// Required
	//
	// Must be non-empty
	RecipientId string `json:"RecipientId"`
}

type EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItemEncryption struct {

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

type EditMessageForwardFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewEditMessageForwardFederationRequestBody(data map[string]any) (EditMessageForwardFederationRequestBody, error) {
	var body EditMessageForwardFederationRequestBody

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

	valUpdatedMessage, ok := data["UpdatedMessage"]
	if !ok {

		return body, fmt.Errorf("missing required field 'UpdatedMessage'")

	} else {

		valUpdatedMessageTypedMap, ok := valUpdatedMessage.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'UpdatedMessage' has incorrect type")
		}
		valUpdatedMessageTyped, err := NewEditMessageForwardFederationRequestBodyUpdatedMessage(valUpdatedMessageTypedMap)
		if err != nil {
			return body, fmt.Errorf("field 'UpdatedMessage' is invalid: %w", err)
		}

		body.UpdatedMessage = valUpdatedMessageTyped

	}

	return body, nil
}

func NewEditMessageForwardFederationRequestBodyUpdatedMessage(data map[string]any) (EditMessageForwardFederationRequestBodyUpdatedMessage, error) {
	var body EditMessageForwardFederationRequestBodyUpdatedMessage

	valMessageContent, ok := data["MessageContent"]
	if !ok {

		return body, fmt.Errorf("missing required field 'MessageContent'")

	} else {

		valMessageContentTypedMap, ok := valMessageContent.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'MessageContent' has incorrect type")
		}
		valMessageContentTyped, err := NewEditMessageForwardFederationRequestBodyUpdatedMessageMessageContent(valMessageContentTypedMap)
		if err != nil {
			return body, fmt.Errorf("field 'MessageContent' is invalid: %w", err)
		}

		body.MessageContent = valMessageContentTyped

	}

	return body, nil
}

func NewEditMessageForwardFederationRequestBodyUpdatedMessageMessageContent(data map[string]any) (EditMessageForwardFederationRequestBodyUpdatedMessageMessageContent, error) {
	var body EditMessageForwardFederationRequestBodyUpdatedMessageMessageContent

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

		valEncryptionDataTyped := make([]EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItem, 0, len(valEncryptionDataSlice))

		for idx, item := range valEncryptionDataSlice {
			itemMap, ok := item.(map[string]any)
			if !ok {
				return body, fmt.Errorf("element %d of field 'EncryptionData' has incorrect type", idx)
			}
			validatedItem, err := NewEditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItem(itemMap)
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

func NewEditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItem(data map[string]any) (EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItem, error) {
	var body EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItem

	valEncryption, ok := data["Encryption"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Encryption'")

	} else {

		valEncryptionTypedMap, ok := valEncryption.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'Encryption' has incorrect type")
		}
		valEncryptionTyped, err := NewEditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItemEncryption(valEncryptionTypedMap)
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

func NewEditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItemEncryption(data map[string]any) (EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItemEncryption, error) {
	var body EditMessageForwardFederationRequestBodyUpdatedMessageMessageContentEncryptionDataItemEncryption

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

// NewEditMessageForwardFederationRequest creates a new EditMessageForwardFederationRequest from an http.Request and performs parameter parsing and validation.
func NewEditMessageForwardFederationRequest(w http.ResponseWriter, r *http.Request) (req EditMessageForwardFederationRequest, err error) {

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
	var body EditMessageForwardFederationRequestBody
	body, err = NewEditMessageForwardFederationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type EditMessageForwardFederation200Response struct {
}

// Message edited successfully from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteEditMessageForwardFederation200Response(w http.ResponseWriter, response EditMessageForwardFederation200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type EditMessageForwardFederation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteEditMessageForwardFederation400Response(w http.ResponseWriter, response EditMessageForwardFederation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type EditMessageForwardFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteEditMessageForwardFederation401Response(w http.ResponseWriter, response EditMessageForwardFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type EditMessageForwardFederation403Response struct {
}

// Forbidden. Requesting server's JWT is not valid (JWT iss domain != sender id domain), or user does not have permission to edit the message, or Receiving server is not conversation owner's server.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteEditMessageForwardFederation403Response(w http.ResponseWriter, response EditMessageForwardFederation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type EditMessageForwardFederation404Response struct {
}

// Conversation or message not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteEditMessageForwardFederation404Response(w http.ResponseWriter, response EditMessageForwardFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type EditMessageForwardFederation500Response struct {
}

// Internal server error while editing the message from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteEditMessageForwardFederation500Response(w http.ResponseWriter, response EditMessageForwardFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
