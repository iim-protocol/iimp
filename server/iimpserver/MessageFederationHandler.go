package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	MessageFederationRequestHTTPMethod = "POST"
	MessageFederationRequestRoutePath  = "/api/federation/conversations/{conversationId}/messages"
)

// \"FEDERATION\" Send a new message/update to an existing message model to a conversation from another server. This endpoint is used by other servers to send messages to a conversation that includes users from the local server. The request will include details about the message and its sender. Upsert operation must be performed by the receiving server.
type MessageFederationRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// Unique identifier of the conversation to send the message to.
	//
	// Required
	ConversationId string

	// Authentication parameters
	Auth MessageFederationRequestAuthParams

	// Request body
	Body MessageFederationRequestBody
}

type MessageFederationRequestBody struct {

	// An optional list of attachments included with the message. Each attachment can be a file, image, or other media type that is associated with the message. The server will store the attachments and deliver them to the recipients along with the message content.
	//
	// Optional
	//
	Attachments []string `json:"Attachments,omitempty"`

	// A list of message contents for the message, ordered by their version in Ascending Order. The original message sent by the client will have version 1. Each time the message is edited, a new MessageContent object is added to this list with the version number incremented by 1. This allows the server and clients to maintain a history of edits for each message, enabling features such as edit history viewing and audit trails.
	//
	// Required
	//
	// Must be non-empty
	Contents []MessageFederationRequestBodyContentsItem `json:"Contents"`

	// The unique identifier of the conversation that the message belongs to. This is typically a UUIDv7.
	//
	// Required
	//
	// Must be non-empty
	ConversationId string `json:"ConversationId"`

	// A flag indicating whether the message has been redacted. Redaction is the process of removing or obscuring the content of a message while retaining its metadata (e.g., sender, timestamp) for record-keeping purposes. A redacted message will have its content removed or replaced with a placeholder value, and the IsRedacted flag will be set to true.
	//
	// Required
	//
	IsRedacted bool `json:"IsRedacted"`

	// A unique identifier for the message, typically a UUIDv7.
	//
	// Required
	//
	// Must be non-empty
	MessageId string `json:"MessageId"`

	// User ID of the sender of the message. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	SenderUserId string `json:"SenderUserId"`

	// The timestamp when the message was originally sent. Format => ISO 8601 (e.g., "2024-06-01T12:00:00Z"). This field is included to provide context about when the message was sent, which can be useful for ordering messages and displaying timestamps in the client applications.
	//
	// Required
	//
	// Must be non-empty
	Timestamp string `json:"Timestamp"`

	// An array of per-user data for each recipient of the message.
	//
	// Required
	//
	// Must be non-empty
	UserSpecificData []MessageFederationRequestBodyUserSpecificDataItem `json:"UserSpecificData"`
}

type MessageFederationRequestBodyContentsItem struct {

	// Required
	//
	MessageContent MessageFederationRequestBodyContentsItemMessageContent `json:"MessageContent"`

	// The version of the message, to support message editing. The original message sent by the client will have version 1. Each time the message is edited, a new MessageContent object is added in the contents array with the version number incremented by 1. This allows the server and clients to maintain a history of edits for each message, enabling features such as edit history viewing and audit trails.
	//
	// Required
	//
	Version float64 `json:"Version"`
}

type MessageFederationRequestBodyContentsItemMessageContent struct {

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
	EncryptionData []MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem `json:"EncryptionData"`

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

type MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem struct {

	// Encryption details for a recipient of the message.
	//
	// Required
	//
	Encryption MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItemEncryption `json:"Encryption"`

	// User ID of the recipient of the message. (localpart@domain). This field is included to associate the encryption details with the specific recipient, allowing the server to deliver the correct encrypted key and nonce to each recipient along with the encrypted message content.
	//
	// Required
	//
	// Must be non-empty
	RecipientId string `json:"RecipientId"`
}

type MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItemEncryption struct {

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

type MessageFederationRequestBodyUserSpecificDataItem struct {

	// The timestamp when the recipient reacted to the message. This field is null if the recipient has not reacted to the message yet. Format => ISO 8601 (e.g., "2024-06-01T12:00:00Z"). This field is included to provide context about when each reaction was made for the message.
	//
	// Optional
	//
	ReactedAt *string `json:"ReactedAt,omitempty"`

	// An optional reaction from the recipient for the message (e.g., "like", "love", "laugh", "sad", "angry", etc.). This field is included to provide message reaction functionality, allowing recipients to react to messages with predefined reactions. The server will store the reaction and deliver it to the sender and other recipients, allowing them to see the reactions for each message. Emoji-Only field.
	//
	// Optional
	//
	Reaction *string `json:"Reaction,omitempty"`

	// The timestamp when the recipient read the message. This field is null if the recipient has not read the message yet. Format => ISO 8601 (e.g., "2024-06-01T12:00:00Z"). This field is included to provide read receipt functionality, allowing the sender to know when each recipient has read the message.
	//
	// Optional
	//
	ReadAt *string `json:"ReadAt,omitempty"`

	// User ID of the recipient of the message. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	RecipientId string `json:"RecipientId"`
}

type MessageFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewMessageFederationRequestBody(data map[string]any) (MessageFederationRequestBody, error) {
	var body MessageFederationRequestBody

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

	valContents, ok := data["Contents"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Contents'")

	} else {

		valContentsSlice, ok := valContents.([]any)
		if !ok {
			return body, fmt.Errorf("field 'Contents' has incorrect type")
		}

		if len(valContentsSlice) == 0 {
			return body, fmt.Errorf("field 'Contents' must be non-empty")
		}

		valContentsTyped := make([]MessageFederationRequestBodyContentsItem, 0, len(valContentsSlice))

		for idx, item := range valContentsSlice {
			itemMap, ok := item.(map[string]any)
			if !ok {
				return body, fmt.Errorf("element %d of field 'Contents' has incorrect type", idx)
			}
			validatedItem, err := NewMessageFederationRequestBodyContentsItem(itemMap)
			if err != nil {
				return body, fmt.Errorf("element %d of field 'Contents' is invalid: %w", idx, err)
			}
			valContentsTyped = append(valContentsTyped, validatedItem)
		}

		body.Contents = valContentsTyped

	}

	valConversationId, ok := data["ConversationId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ConversationId'")

	} else {

		valConversationIdTyped, ok := valConversationId.(string)
		if !ok {
			return body, fmt.Errorf("field 'ConversationId' has incorrect type")
		}

		valConversationIdTyped = strings.TrimSpace(valConversationIdTyped)
		if len(valConversationIdTyped) == 0 {
			return body, fmt.Errorf("field 'ConversationId' must be non-empty")
		}

		body.ConversationId = valConversationIdTyped

	}

	valIsRedacted, ok := data["IsRedacted"]
	if !ok {

		return body, fmt.Errorf("missing required field 'IsRedacted'")

	} else {

		valIsRedactedTyped, ok := valIsRedacted.(bool)
		if !ok {
			return body, fmt.Errorf("field 'IsRedacted' has incorrect type")
		}

		body.IsRedacted = valIsRedactedTyped

	}

	valMessageId, ok := data["MessageId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'MessageId'")

	} else {

		valMessageIdTyped, ok := valMessageId.(string)
		if !ok {
			return body, fmt.Errorf("field 'MessageId' has incorrect type")
		}

		valMessageIdTyped = strings.TrimSpace(valMessageIdTyped)
		if len(valMessageIdTyped) == 0 {
			return body, fmt.Errorf("field 'MessageId' must be non-empty")
		}

		body.MessageId = valMessageIdTyped

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

	valUserSpecificData, ok := data["UserSpecificData"]
	if !ok {

		return body, fmt.Errorf("missing required field 'UserSpecificData'")

	} else {

		valUserSpecificDataSlice, ok := valUserSpecificData.([]any)
		if !ok {
			return body, fmt.Errorf("field 'UserSpecificData' has incorrect type")
		}

		if len(valUserSpecificDataSlice) == 0 {
			return body, fmt.Errorf("field 'UserSpecificData' must be non-empty")
		}

		valUserSpecificDataTyped := make([]MessageFederationRequestBodyUserSpecificDataItem, 0, len(valUserSpecificDataSlice))

		for idx, item := range valUserSpecificDataSlice {
			itemMap, ok := item.(map[string]any)
			if !ok {
				return body, fmt.Errorf("element %d of field 'UserSpecificData' has incorrect type", idx)
			}
			validatedItem, err := NewMessageFederationRequestBodyUserSpecificDataItem(itemMap)
			if err != nil {
				return body, fmt.Errorf("element %d of field 'UserSpecificData' is invalid: %w", idx, err)
			}
			valUserSpecificDataTyped = append(valUserSpecificDataTyped, validatedItem)
		}

		body.UserSpecificData = valUserSpecificDataTyped

	}

	return body, nil
}

func NewMessageFederationRequestBodyContentsItem(data map[string]any) (MessageFederationRequestBodyContentsItem, error) {
	var body MessageFederationRequestBodyContentsItem

	valMessageContent, ok := data["MessageContent"]
	if !ok {

		return body, fmt.Errorf("missing required field 'MessageContent'")

	} else {

		valMessageContentTypedMap, ok := valMessageContent.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'MessageContent' has incorrect type")
		}
		valMessageContentTyped, err := NewMessageFederationRequestBodyContentsItemMessageContent(valMessageContentTypedMap)
		if err != nil {
			return body, fmt.Errorf("field 'MessageContent' is invalid: %w", err)
		}

		body.MessageContent = valMessageContentTyped

	}

	valVersion, ok := data["Version"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Version'")

	} else {

		valVersionTyped, ok := valVersion.(float64)
		if !ok {
			return body, fmt.Errorf("field 'Version' has incorrect type")
		}

		body.Version = valVersionTyped

	}

	return body, nil
}

func NewMessageFederationRequestBodyContentsItemMessageContent(data map[string]any) (MessageFederationRequestBodyContentsItemMessageContent, error) {
	var body MessageFederationRequestBodyContentsItemMessageContent

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

		valEncryptionDataTyped := make([]MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem, 0, len(valEncryptionDataSlice))

		for idx, item := range valEncryptionDataSlice {
			itemMap, ok := item.(map[string]any)
			if !ok {
				return body, fmt.Errorf("element %d of field 'EncryptionData' has incorrect type", idx)
			}
			validatedItem, err := NewMessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem(itemMap)
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

func NewMessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem(data map[string]any) (MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem, error) {
	var body MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem

	valEncryption, ok := data["Encryption"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Encryption'")

	} else {

		valEncryptionTypedMap, ok := valEncryption.(map[string]any)
		if !ok {
			return body, fmt.Errorf("field 'Encryption' has incorrect type")
		}
		valEncryptionTyped, err := NewMessageFederationRequestBodyContentsItemMessageContentEncryptionDataItemEncryption(valEncryptionTypedMap)
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

func NewMessageFederationRequestBodyContentsItemMessageContentEncryptionDataItemEncryption(data map[string]any) (MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItemEncryption, error) {
	var body MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItemEncryption

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

func NewMessageFederationRequestBodyUserSpecificDataItem(data map[string]any) (MessageFederationRequestBodyUserSpecificDataItem, error) {
	var body MessageFederationRequestBodyUserSpecificDataItem

	valReactedAt, ok := data["ReactedAt"]
	if !ok {

		// skip, leave as zero value

	} else {

		valReactedAtTyped, ok := valReactedAt.(string)
		if !ok {
			return body, fmt.Errorf("field 'ReactedAt' has incorrect type")
		}

		body.ReactedAt = &valReactedAtTyped

	}

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

	valReadAt, ok := data["ReadAt"]
	if !ok {

		// skip, leave as zero value

	} else {

		valReadAtTyped, ok := valReadAt.(string)
		if !ok {
			return body, fmt.Errorf("field 'ReadAt' has incorrect type")
		}

		body.ReadAt = &valReadAtTyped

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

// NewMessageFederationRequest creates a new MessageFederationRequest from an http.Request and performs parameter parsing and validation.
func NewMessageFederationRequest(w http.ResponseWriter, r *http.Request) (req MessageFederationRequest, err error) {

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
	var body MessageFederationRequestBody
	body, err = NewMessageFederationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type MessageFederation200Response struct {
}

// Message stored/updated successfully from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageFederation200Response(w http.ResponseWriter, response MessageFederation200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type MessageFederation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageFederation400Response(w http.ResponseWriter, response MessageFederation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type MessageFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageFederation401Response(w http.ResponseWriter, response MessageFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type MessageFederation403Response struct {
}

// Forbidden. Requesting server's JWT is not valid (JWT iss domain != conversation owner id domain).
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageFederation403Response(w http.ResponseWriter, response MessageFederation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type MessageFederation404Response struct {
}

// Conversation not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageFederation404Response(w http.ResponseWriter, response MessageFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type MessageFederation500Response struct {
}

// Internal server error while sending the message from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteMessageFederation500Response(w http.ResponseWriter, response MessageFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
