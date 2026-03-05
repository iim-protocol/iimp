package iimp_go_client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type IIMPErrorReason string

const (
	IIMPErrorReasonInvalidRequest IIMPErrorReason = "invalid_request"
	IIMPErrorReasonDecodeError    IIMPErrorReason = "decode_error"
	IIMPErrorReasonNetworkError   IIMPErrorReason = "network_error"
	IIMPErrorReasonOtherError     IIMPErrorReason = "other_error"
)

type IIMPError struct {
	Reason  IIMPErrorReason
	Message string
	Err     error
}

func (e *IIMPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Reason, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Reason, e.Message)
}

const (
	AddPublicKeyRequestHTTPMethod = "POST"
	AddPublicKeyRequestRoutePath  = "/iimp/api/client/keys"
)

// Add a new public key for end-to-end encryption.
type AddPublicKeyRequest struct {

	// Authentication parameters
	Auth AddPublicKeyRequestAuthParams

	// Request body
	Body AddPublicKeyRequestBody
}

type AddPublicKeyRequestBody struct {

	// The public key to be added for end-to-end encryption. The key should be Base64URL Encoded X25519 Key.
	//
	// Required
	//
	// Must be non-empty
	PublicKey string `json:"PublicKey"`
}

type AddPublicKeyRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *AddPublicKeyRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

func (o *AddPublicKeyRequestBody) Validate() error {

	if strings.TrimSpace(o.PublicKey) == "" {
		return fmt.Errorf("field 'PublicKey' must be non-empty")
	}

	return nil
}

type AddPublicKey201Response struct {

	// Response body
	Body AddPublicKey201ResponseBody
}

type AddPublicKey201ResponseBody struct {

	// A unique identifier for the uploaded public key. This ID can be used to reference the key in future operations, such as encrypting messages for specific recipients or managing keys.
	//
	// Required
	//
	// Must be non-empty
	KeyId string `json:"KeyId"`

	// The timestamp when the public key was uploaded to the server. This can be used to determine the age of the key and manage key rotation policies.
	//
	// Required
	//
	UploadedAt string `json:"UploadedAt"`
}

func NewAddPublicKey201Response(resp *http.Response) (AddPublicKey201Response, error) {
	defer resp.Body.Close()
	result := AddPublicKey201Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type AddPublicKey400Response struct {
}

func NewAddPublicKey400Response(resp *http.Response) (AddPublicKey400Response, error) {
	defer resp.Body.Close()
	result := AddPublicKey400Response{}

	return result, nil
}

type AddPublicKey401Response struct {
}

func NewAddPublicKey401Response(resp *http.Response) (AddPublicKey401Response, error) {
	defer resp.Body.Close()
	result := AddPublicKey401Response{}

	return result, nil
}

type AddPublicKey500Response struct {
}

func NewAddPublicKey500Response(resp *http.Response) (AddPublicKey500Response, error) {
	defer resp.Body.Close()
	result := AddPublicKey500Response{}

	return result, nil
}

const (
	ConversationFederationRequestHTTPMethod = "POST"
	ConversationFederationRequestRoutePath  = "/iimp/api/federation/conversations"
)

// \"FEDERATION\" Create/Update a conversation from another server. This endpoint is used by other servers to create/update a conversation that includes users from the local server. UPSERT operation should be performed by the receiving server.
type ConversationFederationRequest struct {

	// Authentication parameters
	Auth ConversationFederationRequestAuthParams

	// Request body
	Body ConversationFederationRequestBody
}

type ConversationFederationRequestBody struct {

	// A unique identifier for the conversation.
	//
	// Required
	//
	// Must be non-empty
	ConversationId string `json:"ConversationId"`

	// An optional name for the conversation, which can be set by the client. This is not used for identification purposes and can be changed by the owner user at any time.
	//
	// Optional
	//
	ConversationName *string `json:"ConversationName,omitempty"`

	// The user ID of the owner of the conversation. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	ConversationOwnerId string `json:"ConversationOwnerId"`

	// The timestamp when the conversation was created. Format => RFC3339.
	//
	// Required
	//
	// Must be non-empty
	CreatedAt string `json:"CreatedAt"`

	// A flag indicating whether the conversation is a Direct Message (DM) or a Group Conversation. A Direct Message conversation has exactly 2 participants (including the owner), while a Group Conversation has more than 2 participants.
	//
	// Required
	//
	IsDM bool `json:"IsDM"`

	// A list of participants in the conversation. The owner of the conversation is also included in this list. Participants can be added or removed by the owner user. Contains at least 2 participants (including the owner) for a Direct Conversation and >2 participants for a Group Conversation.
	//
	// Required
	//
	// Must be non-empty
	Participants []ConversationFederationRequestBodyParticipantsItem `json:"Participants"`
}

type ConversationFederationRequestBodyParticipantsItem struct {

	// The timestamp when the participant joined the conversation. Format => RFC3339.
	//
	// Required
	//
	// Must be non-empty
	JoinedAt string `json:"JoinedAt"`

	// The timestamp when the participant was removed from the conversation. This field is null if the participant is still part of the conversation. Format => RFC3339. A removed participant will not receive new messages in the conversation but can still access the conversation history up until the time they were removed. Owner CANNOT be removed from the conversation.
	//
	// Optional
	//
	RemovedAt *string `json:"RemovedAt,omitempty"`

	// This is the display name of the participant at the time they joined the conversation. This is not updated if the user changes their display name later. This field is included to provide context about the participant's identity within the conversation, even if their global display name changes over time. During federation, the owner's server contacts the participant's server to fetch the current display name of the participant, which is then stored as UserDisplayName in the conversation participant list. This allows the conversation to maintain a consistent display name for the participant, even if they change their display name globally on their server.
	//
	// Required
	//
	// Must be non-empty
	UserDisplayName string `json:"UserDisplayName"`

	// User ID of the participant. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

type ConversationFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *ConversationFederationRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

func (o *ConversationFederationRequestBody) Validate() error {

	if strings.TrimSpace(o.ConversationId) == "" {
		return fmt.Errorf("field 'ConversationId' must be non-empty")
	}

	if strings.TrimSpace(o.ConversationOwnerId) == "" {
		return fmt.Errorf("field 'ConversationOwnerId' must be non-empty")
	}

	if strings.TrimSpace(o.CreatedAt) == "" {
		return fmt.Errorf("field 'CreatedAt' must be non-empty")
	}

	if len(o.Participants) == 0 {
		return fmt.Errorf("field 'Participants' must be non-empty")
	}

	for idx, item := range o.Participants {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("element %d of field 'Participants' is invalid: %w", idx, err)
		}
	}

	return nil
}
func (o *ConversationFederationRequestBodyParticipantsItem) Validate() error {

	if strings.TrimSpace(o.JoinedAt) == "" {
		return fmt.Errorf("field 'JoinedAt' must be non-empty")
	}

	if strings.TrimSpace(o.UserDisplayName) == "" {
		return fmt.Errorf("field 'UserDisplayName' must be non-empty")
	}

	if strings.TrimSpace(o.UserId) == "" {
		return fmt.Errorf("field 'UserId' must be non-empty")
	}

	return nil
}

type ConversationFederation200Response struct {
}

func NewConversationFederation200Response(resp *http.Response) (ConversationFederation200Response, error) {
	defer resp.Body.Close()
	result := ConversationFederation200Response{}

	return result, nil
}

type ConversationFederation400Response struct {
}

func NewConversationFederation400Response(resp *http.Response) (ConversationFederation400Response, error) {
	defer resp.Body.Close()
	result := ConversationFederation400Response{}

	return result, nil
}

type ConversationFederation401Response struct {
}

func NewConversationFederation401Response(resp *http.Response) (ConversationFederation401Response, error) {
	defer resp.Body.Close()
	result := ConversationFederation401Response{}

	return result, nil
}

type ConversationFederation403Response struct {
}

func NewConversationFederation403Response(resp *http.Response) (ConversationFederation403Response, error) {
	defer resp.Body.Close()
	result := ConversationFederation403Response{}

	return result, nil
}

type ConversationFederation404Response struct {
}

func NewConversationFederation404Response(resp *http.Response) (ConversationFederation404Response, error) {
	defer resp.Body.Close()
	result := ConversationFederation404Response{}

	return result, nil
}

type ConversationFederation500Response struct {
}

func NewConversationFederation500Response(resp *http.Response) (ConversationFederation500Response, error) {
	defer resp.Body.Close()
	result := ConversationFederation500Response{}

	return result, nil
}

const (
	DiscoverServerRequestHTTPMethod = "GET"
	DiscoverServerRequestRoutePath  = "/.well-known/iimp"
)

// Retrieve information about the IIMP server, including protocol version, domain, and federation endpoint. This allows clients and other servers to discover the capabilities and federation details of the server.
type DiscoverServerRequest struct {
}

func (req *DiscoverServerRequest) Validate() error {

	// Authentication parameters validation

	return nil
}

type DiscoverServer200Response struct {

	// Response body
	Body DiscoverServer200ResponseBody
}

type DiscoverServer200ResponseBody struct {

	// Canonical domain name of the server. Includes the scheme, e.g. https://server-a.domain1.me
	//
	// Required
	//
	// Must be non-empty
	Domain string `json:"Domain"`

	// IIMP protocol version supported by the server.
	//
	// Required
	//
	// Must be non-empty
	Version string `json:"Version"`
}

func NewDiscoverServer200Response(resp *http.Response) (DiscoverServer200Response, error) {
	defer resp.Body.Close()
	result := DiscoverServer200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type DiscoverServer404Response struct {
}

func NewDiscoverServer404Response(resp *http.Response) (DiscoverServer404Response, error) {
	defer resp.Body.Close()
	result := DiscoverServer404Response{}

	return result, nil
}

type DiscoverServer500Response struct {
}

func NewDiscoverServer500Response(resp *http.Response) (DiscoverServer500Response, error) {
	defer resp.Body.Close()
	result := DiscoverServer500Response{}

	return result, nil
}

const (
	DownloadAttachmentRequestHTTPMethod = "GET"
	DownloadAttachmentRequestRoutePath  = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/attachments/{fileId}/bytes"
)

// Download the bytes of an attachment for a message in a conversation. This is a NOOP endpoint for documentation, since the actual fetching of the attachment bytes is to be done by the client.
type DownloadAttachmentRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message that the attachment belongs to.
	//
	// Required
	MessageId string

	// Source: path parameter "{fileId}"
	//

	// The unique identifier of the file to fetch. This should correspond to an attachment that was previously uploaded to the server using the UploadAttachment endpoint.
	//
	// Required
	FileId string

	// Authentication parameters
	Auth DownloadAttachmentRequestAuthParams
}

type DownloadAttachmentRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *DownloadAttachmentRequest) Validate() error {

	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

type DownloadAttachment200Response struct {
}

func NewDownloadAttachment200Response(resp *http.Response) (DownloadAttachment200Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachment200Response{}

	return result, nil
}

type DownloadAttachment400Response struct {
}

func NewDownloadAttachment400Response(resp *http.Response) (DownloadAttachment400Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachment400Response{}

	return result, nil
}

type DownloadAttachment401Response struct {
}

func NewDownloadAttachment401Response(resp *http.Response) (DownloadAttachment401Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachment401Response{}

	return result, nil
}

type DownloadAttachment403Response struct {
}

func NewDownloadAttachment403Response(resp *http.Response) (DownloadAttachment403Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachment403Response{}

	return result, nil
}

type DownloadAttachment404Response struct {
}

func NewDownloadAttachment404Response(resp *http.Response) (DownloadAttachment404Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachment404Response{}

	return result, nil
}

type DownloadAttachment500Response struct {
}

func NewDownloadAttachment500Response(resp *http.Response) (DownloadAttachment500Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachment500Response{}

	return result, nil
}

const (
	DownloadAttachmentBytesFederationRequestHTTPMethod = "GET"
	DownloadAttachmentBytesFederationRequestRoutePath  = "/iimp/api/federation/conversations/{conversationId}/messages/{messageId}/attachments/{fileId}/bytes"
)

// \"FEDERATION\" Download the bytes of an attachment from another server. This is a noop endpoint for documentation purposes, the server should implement fetching the actual bytes using the provided endpoint. Server must implement this, requesting server needs to fetch the bytes NOT using the SDK.
type DownloadAttachmentBytesFederationRequest struct {

	// Source: path parameter "{fileId}"
	//

	// Unique identifier of the file to fetch.
	//
	// Required
	FileId string

	// Source: path parameter "{messageId}"
	//

	// Unique identifier of the message that the file/attachment belongs to.
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
	Auth DownloadAttachmentBytesFederationRequestAuthParams
}

type DownloadAttachmentBytesFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *DownloadAttachmentBytesFederationRequest) Validate() error {

	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

type DownloadAttachmentBytesFederation200Response struct {
}

func NewDownloadAttachmentBytesFederation200Response(resp *http.Response) (DownloadAttachmentBytesFederation200Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachmentBytesFederation200Response{}

	return result, nil
}

type DownloadAttachmentBytesFederation400Response struct {
}

func NewDownloadAttachmentBytesFederation400Response(resp *http.Response) (DownloadAttachmentBytesFederation400Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachmentBytesFederation400Response{}

	return result, nil
}

type DownloadAttachmentBytesFederation401Response struct {
}

func NewDownloadAttachmentBytesFederation401Response(resp *http.Response) (DownloadAttachmentBytesFederation401Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachmentBytesFederation401Response{}

	return result, nil
}

type DownloadAttachmentBytesFederation403Response struct {
}

func NewDownloadAttachmentBytesFederation403Response(resp *http.Response) (DownloadAttachmentBytesFederation403Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachmentBytesFederation403Response{}

	return result, nil
}

type DownloadAttachmentBytesFederation404Response struct {
}

func NewDownloadAttachmentBytesFederation404Response(resp *http.Response) (DownloadAttachmentBytesFederation404Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachmentBytesFederation404Response{}

	return result, nil
}

type DownloadAttachmentBytesFederation500Response struct {
}

func NewDownloadAttachmentBytesFederation500Response(resp *http.Response) (DownloadAttachmentBytesFederation500Response, error) {
	defer resp.Body.Close()
	result := DownloadAttachmentBytesFederation500Response{}

	return result, nil
}

const (
	EditMessageRequestHTTPMethod = "PUT"
	EditMessageRequestRoutePath  = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}"
)

// Edit an existing message in a conversation. Only the sender of the message can edit it.
type EditMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message to edit.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth EditMessageRequestAuthParams

	// Request body
	Body EditMessageRequestBody
}

type EditMessageRequestBody struct {

	// Required
	//
	MessageContent EditMessageRequestBodyMessageContent `json:"MessageContent"`
}

type EditMessageRequestBodyMessageContent struct {

	// The content of the message to be sent in the conversation. The content should be encrypted using an AES key, and the AES key should be encrypted for each recipient using their respective public keys. The server will store the encrypted message content and the encrypted keys for each recipient, allowing the recipients to decrypt the AES key using their private keys and then use it to decrypt the message content.
	//
	// Required
	//
	// Must be non-empty
	Content string `json:"Content"`

	// Encryption details for the recipients of the message. The sender client should not include details for participants of a convo where RemovedAt != nil.
	//
	// Required
	//
	// Must be non-empty
	EncryptionData []EditMessageRequestBodyMessageContentEncryptionDataItem `json:"EncryptionData"`

	// The nonce (or initialization vector) used in the AES encryption of the message content. This should be a unique value for each message encrypted with the same AES key to ensure security. The nonce is required for the decryption process, as it is used along with the AES key to decrypt the message content. The server will store the nonce along with the encrypted message content and deliver it to the recipients, allowing them to use it in the decryption process. The nonce should be generated securely (e.g., using a cryptographically secure random number generator) and should be of 12 bytes (96 bits) in length for AES-256-GCM encryption.
	//
	// Required
	//
	// Must be non-empty
	Nonce string `json:"Nonce"`

	// The timestamp when the message content was created. Format => RFC3339. This field is included to provide context about when the message content was created, which can be useful for ordering messages and displaying timestamps in the client applications.
	//
	// Required
	//
	// Must be non-empty
	Timestamp string `json:"Timestamp"`
}

type EditMessageRequestBodyMessageContentEncryptionDataItem struct {

	// Encryption details for a recipient of the message.
	//
	// Required
	//
	Encryption EditMessageRequestBodyMessageContentEncryptionDataItemEncryption `json:"Encryption"`

	// User ID of the recipient of the message. (localpart@domain). This field is included to associate the encryption details with the specific recipient, allowing the server to deliver the correct encrypted key and nonce to each recipient along with the encrypted message content.
	//
	// Required
	//
	// Must be non-empty
	RecipientId string `json:"RecipientId"`
}

type EditMessageRequestBodyMessageContentEncryptionDataItemEncryption struct {

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

type EditMessageRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *EditMessageRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

func (o *EditMessageRequestBody) Validate() error {

	if err := o.MessageContent.Validate(); err != nil {
		return fmt.Errorf("field 'MessageContent' is invalid: %w", err)
	}

	return nil
}
func (o *EditMessageRequestBodyMessageContent) Validate() error {

	if strings.TrimSpace(o.Content) == "" {
		return fmt.Errorf("field 'Content' must be non-empty")
	}

	if len(o.EncryptionData) == 0 {
		return fmt.Errorf("field 'EncryptionData' must be non-empty")
	}

	for idx, item := range o.EncryptionData {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("element %d of field 'EncryptionData' is invalid: %w", idx, err)
		}
	}

	if strings.TrimSpace(o.Nonce) == "" {
		return fmt.Errorf("field 'Nonce' must be non-empty")
	}

	if strings.TrimSpace(o.Timestamp) == "" {
		return fmt.Errorf("field 'Timestamp' must be non-empty")
	}

	return nil
}
func (o *EditMessageRequestBodyMessageContentEncryptionDataItem) Validate() error {

	if err := o.Encryption.Validate(); err != nil {
		return fmt.Errorf("field 'Encryption' is invalid: %w", err)
	}

	if strings.TrimSpace(o.RecipientId) == "" {
		return fmt.Errorf("field 'RecipientId' must be non-empty")
	}

	return nil
}
func (o *EditMessageRequestBodyMessageContentEncryptionDataItemEncryption) Validate() error {

	if strings.TrimSpace(o.EncryptedKey) == "" {
		return fmt.Errorf("field 'EncryptedKey' must be non-empty")
	}

	if strings.TrimSpace(o.EncryptedKeyNonce) == "" {
		return fmt.Errorf("field 'EncryptedKeyNonce' must be non-empty")
	}

	if strings.TrimSpace(o.EphemeralPublicKey) == "" {
		return fmt.Errorf("field 'EphemeralPublicKey' must be non-empty")
	}

	if strings.TrimSpace(o.KeyId) == "" {
		return fmt.Errorf("field 'KeyId' must be non-empty")
	}

	return nil
}

type EditMessage200Response struct {
}

func NewEditMessage200Response(resp *http.Response) (EditMessage200Response, error) {
	defer resp.Body.Close()
	result := EditMessage200Response{}

	return result, nil
}

type EditMessage400Response struct {
}

func NewEditMessage400Response(resp *http.Response) (EditMessage400Response, error) {
	defer resp.Body.Close()
	result := EditMessage400Response{}

	return result, nil
}

type EditMessage401Response struct {
}

func NewEditMessage401Response(resp *http.Response) (EditMessage401Response, error) {
	defer resp.Body.Close()
	result := EditMessage401Response{}

	return result, nil
}

type EditMessage403Response struct {
}

func NewEditMessage403Response(resp *http.Response) (EditMessage403Response, error) {
	defer resp.Body.Close()
	result := EditMessage403Response{}

	return result, nil
}

type EditMessage404Response struct {
}

func NewEditMessage404Response(resp *http.Response) (EditMessage404Response, error) {
	defer resp.Body.Close()
	result := EditMessage404Response{}

	return result, nil
}

type EditMessage500Response struct {
}

func NewEditMessage500Response(resp *http.Response) (EditMessage500Response, error) {
	defer resp.Body.Close()
	result := EditMessage500Response{}

	return result, nil
}

const (
	GetJWKSStoreRequestHTTPMethod = "GET"
	GetJWKSStoreRequestRoutePath  = "/.well-known/iimp/jwks"
)

// Retrieve the JSON Web Key Set (JWKS) containing the public keys used by the server for verifying signatures. This is used in the federation process to ensure secure communication between servers.
type GetJWKSStoreRequest struct {
}

func (req *GetJWKSStoreRequest) Validate() error {

	// Authentication parameters validation

	return nil
}

type GetJWKSStore200Response struct {

	// Response body
	Body GetJWKSStore200ResponseBody
}

type GetJWKSStore200ResponseBodyKeysItem struct {

	// The algorithm used with this key. For example, "RS256" or "EdDSA".
	//
	// Required
	//
	// Must be non-empty
	Alg string `json:"Alg"`

	// Elliptic curve name (e.g., "Ed25519" or "X25519"). Required if Kty is "OKP".
	//
	// Optional
	//
	Crv *string `json:"Crv,omitempty"`

	// RSA public exponent (base64url encoded). Required if Kty is "RSA".
	//
	// Optional
	//
	E *string `json:"E,omitempty"`

	// Unique identifier for the key. Used to match the 'kid' field in JWT headers.
	//
	// Required
	//
	// Must be non-empty
	Kid string `json:"Kid"`

	// The key type. For example, "RSA" or "OKP".
	//
	// Required
	//
	// Must be non-empty
	Kty string `json:"Kty"`

	// RSA modulus (base64url encoded). Required if Kty is "RSA".
	//
	// Optional
	//
	N *string `json:"N,omitempty"`

	// The intended use of the key. Typically "sig" for signature verification.
	//
	// Required
	//
	// Must be non-empty
	Use string `json:"Use"`

	// Public key value (base64url encoded). Required if Kty is "OKP".
	//
	// Optional
	//
	X *string `json:"X,omitempty"`
}

type GetJWKSStore200ResponseBody struct {

	// A list of JSON Web Keys (JWK) used to verify signatures issued by this server.
	//
	// Required
	//
	// Must be non-empty
	Keys []GetJWKSStore200ResponseBodyKeysItem `json:"Keys"`
}

func NewGetJWKSStore200Response(resp *http.Response) (GetJWKSStore200Response, error) {
	defer resp.Body.Close()
	result := GetJWKSStore200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type GetJWKSStore500Response struct {
}

func NewGetJWKSStore500Response(resp *http.Response) (GetJWKSStore500Response, error) {
	defer resp.Body.Close()
	result := GetJWKSStore500Response{}

	return result, nil
}

const (
	GetUserInfoFederationRequestHTTPMethod = "GET"
	GetUserInfoFederationRequestRoutePath  = "/iimp/api/federation/users/{userId}"
)

// \"FEDERATION\" Retrieve information about a user for federation purposes. This endpoint is used by other servers to fetch details about a user, such as their display name and more.
type GetUserInfoFederationRequest struct {

	// Source: path parameter "{userId}"
	//

	// Unique identifier of the user whose information is being requested. This should be in the format localpart@domain.
	//
	// Required
	UserId string

	// Authentication parameters
	Auth GetUserInfoFederationRequestAuthParams
}

type GetUserInfoFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *GetUserInfoFederationRequest) Validate() error {

	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

type GetUserInfoFederation200Response struct {

	// Response body
	Body GetUserInfoFederation200ResponseBody
}

type GetUserInfoFederation200ResponseBody struct {

	// Display name of the user.
	//
	// Required
	//
	// Must be non-empty
	DisplayName string `json:"DisplayName"`

	// User ID of the user. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func NewGetUserInfoFederation200Response(resp *http.Response) (GetUserInfoFederation200Response, error) {
	defer resp.Body.Close()
	result := GetUserInfoFederation200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type GetUserInfoFederation401Response struct {
}

func NewGetUserInfoFederation401Response(resp *http.Response) (GetUserInfoFederation401Response, error) {
	defer resp.Body.Close()
	result := GetUserInfoFederation401Response{}

	return result, nil
}

type GetUserInfoFederation404Response struct {
}

func NewGetUserInfoFederation404Response(resp *http.Response) (GetUserInfoFederation404Response, error) {
	defer resp.Body.Close()
	result := GetUserInfoFederation404Response{}

	return result, nil
}

type GetUserInfoFederation500Response struct {
}

func NewGetUserInfoFederation500Response(resp *http.Response) (GetUserInfoFederation500Response, error) {
	defer resp.Body.Close()
	result := GetUserInfoFederation500Response{}

	return result, nil
}

const (
	GetUserPublicKeyRequestHTTPMethod = "GET"
	GetUserPublicKeyRequestRoutePath  = "/.well-known/iimp/keys/users/{userId}"
)

// Retrieve the latest/most recent public key associated with a specific user.
type GetUserPublicKeyRequest struct {

	// Source: path parameter "{userId}"
	//

	// Unique identifier of the user whose public key is being requested. This should be in the format localpart@domain.
	//
	// Required
	UserId string
}

func (req *GetUserPublicKeyRequest) Validate() error {

	// Authentication parameters validation

	return nil
}

type GetUserPublicKey200Response struct {

	// Response body
	Body GetUserPublicKey200ResponseBody
}

type GetUserPublicKey200ResponseBody struct {

	// Unique identifier for the public key.
	//
	// Required
	//
	// Must be non-empty
	KeyId string `json:"KeyId"`

	// The actual public key data, encoded in a suitable format (X25519 public key encoded in Base64URL format).
	//
	// Required
	//
	// Must be non-empty
	PublicKey string `json:"PublicKey"`

	// Timestamp indicating when the public key was uploaded, in RFC3339 format.
	//
	// Required
	//
	// Must be non-empty
	UploadedAt string `json:"UploadedAt"`

	// Unique identifier of the user to whom the public key belongs. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func NewGetUserPublicKey200Response(resp *http.Response) (GetUserPublicKey200Response, error) {
	defer resp.Body.Close()
	result := GetUserPublicKey200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type GetUserPublicKey400Response struct {
}

func NewGetUserPublicKey400Response(resp *http.Response) (GetUserPublicKey400Response, error) {
	defer resp.Body.Close()
	result := GetUserPublicKey400Response{}

	return result, nil
}

type GetUserPublicKey404Response struct {
}

func NewGetUserPublicKey404Response(resp *http.Response) (GetUserPublicKey404Response, error) {
	defer resp.Body.Close()
	result := GetUserPublicKey404Response{}

	return result, nil
}

type GetUserPublicKey500Response struct {
}

func NewGetUserPublicKey500Response(resp *http.Response) (GetUserPublicKey500Response, error) {
	defer resp.Body.Close()
	result := GetUserPublicKey500Response{}

	return result, nil
}

const (
	GetUserPublicKeyByIdRequestHTTPMethod = "GET"
	GetUserPublicKeyByIdRequestRoutePath  = "/.well-known/iimp/keys/users/{userId}/{keyId}"
)

// Retrieve a specific public key associated with a user, identified by its key ID. Used for historical key retrieval.
type GetUserPublicKeyByIdRequest struct {

	// Source: path parameter "{userId}"
	//

	// Unique identifier of the user whose public key is being requested. This should be in the format localpart@domain.
	//
	// Required
	UserId string

	// Source: path parameter "{keyId}"
	//

	// Unique identifier for the specific public key to retrieve. This allows clients to fetch historical keys if needed.
	//
	// Required
	KeyId string
}

func (req *GetUserPublicKeyByIdRequest) Validate() error {

	// Authentication parameters validation

	return nil
}

type GetUserPublicKeyById200Response struct {

	// Response body
	Body GetUserPublicKeyById200ResponseBody
}

type GetUserPublicKeyById200ResponseBody struct {

	// Unique identifier for the public key.
	//
	// Required
	//
	// Must be non-empty
	KeyId string `json:"KeyId"`

	// The actual public key data, encoded in a suitable format (X25519 public key encoded in Base64URL format).
	//
	// Required
	//
	// Must be non-empty
	PublicKey string `json:"PublicKey"`

	// Timestamp indicating when the public key was uploaded, in RFC3339 format.
	//
	// Required
	//
	// Must be non-empty
	UploadedAt string `json:"UploadedAt"`

	// Unique identifier of the user to whom the public key belongs. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func NewGetUserPublicKeyById200Response(resp *http.Response) (GetUserPublicKeyById200Response, error) {
	defer resp.Body.Close()
	result := GetUserPublicKeyById200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type GetUserPublicKeyById400Response struct {
}

func NewGetUserPublicKeyById400Response(resp *http.Response) (GetUserPublicKeyById400Response, error) {
	defer resp.Body.Close()
	result := GetUserPublicKeyById400Response{}

	return result, nil
}

type GetUserPublicKeyById404Response struct {
}

func NewGetUserPublicKeyById404Response(resp *http.Response) (GetUserPublicKeyById404Response, error) {
	defer resp.Body.Close()
	result := GetUserPublicKeyById404Response{}

	return result, nil
}

type GetUserPublicKeyById500Response struct {
}

func NewGetUserPublicKeyById500Response(resp *http.Response) (GetUserPublicKeyById500Response, error) {
	defer resp.Body.Close()
	result := GetUserPublicKeyById500Response{}

	return result, nil
}

const (
	LoginRequestHTTPMethod = "POST"
	LoginRequestRoutePath  = "/iimp/api/client/login"
)

// Authenticate a user and establish a session.
type LoginRequest struct {

	// Request body
	Body LoginRequestBody
}

type LoginRequestBody struct {

	// Password for the account.
	//
	// Required
	//
	// Must be non-empty
	Password string `json:"Password"`

	// User ID for the account. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func (req *LoginRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	return nil
}

func (o *LoginRequestBody) Validate() error {

	if strings.TrimSpace(o.Password) == "" {
		return fmt.Errorf("field 'Password' must be non-empty")
	}

	if strings.TrimSpace(o.UserId) == "" {
		return fmt.Errorf("field 'UserId' must be non-empty")
	}

	return nil
}

type Login200Response struct {

	// Response body
	Body Login200ResponseBody
}

type Login200ResponseBody struct {

	// A new token used to refresh the session token when it expires. Previous refresh tokens are invalidated when a new refresh token is issued.
	//
	// Required
	//
	// Must be non-empty
	RefreshToken string `json:"RefreshToken"`

	// The timestamp of when the refresh token expires. Format => RFC3339
	//
	// Required
	//
	RefreshTokenExpiry string `json:"RefreshTokenExpiry"`

	// A new token used to authenticate the client session. This token must be included in the header of subsequent requests to access protected resources.
	//
	// Required
	//
	// Must be non-empty
	SessionToken string `json:"SessionToken"`

	// The timestamp of when the session token expires. Format => RFC3339
	//
	// Required
	//
	SessionTokenExpiry string `json:"SessionTokenExpiry"`
}

func NewLogin200Response(resp *http.Response) (Login200Response, error) {
	defer resp.Body.Close()
	result := Login200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type Login400Response struct {
}

func NewLogin400Response(resp *http.Response) (Login400Response, error) {
	defer resp.Body.Close()
	result := Login400Response{}

	return result, nil
}

type Login401Response struct {
}

func NewLogin401Response(resp *http.Response) (Login401Response, error) {
	defer resp.Body.Close()
	result := Login401Response{}

	return result, nil
}

type Login500Response struct {
}

func NewLogin500Response(resp *http.Response) (Login500Response, error) {
	defer resp.Body.Close()
	result := Login500Response{}

	return result, nil
}

const (
	LogoutRequestHTTPMethod = "POST"
	LogoutRequestRoutePath  = "/iimp/api/client/logout"
)

// Log out the current user and invalidate the session.
type LogoutRequest struct {

	// Authentication parameters
	Auth LogoutRequestAuthParams
}

type LogoutRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *LogoutRequest) Validate() error {

	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

type Logout204Response struct {
}

func NewLogout204Response(resp *http.Response) (Logout204Response, error) {
	defer resp.Body.Close()
	result := Logout204Response{}

	return result, nil
}

type Logout400Response struct {
}

func NewLogout400Response(resp *http.Response) (Logout400Response, error) {
	defer resp.Body.Close()
	result := Logout400Response{}

	return result, nil
}

type Logout401Response struct {
}

func NewLogout401Response(resp *http.Response) (Logout401Response, error) {
	defer resp.Body.Close()
	result := Logout401Response{}

	return result, nil
}

type Logout500Response struct {
}

func NewLogout500Response(resp *http.Response) (Logout500Response, error) {
	defer resp.Body.Close()
	result := Logout500Response{}

	return result, nil
}

const (
	MessageFederationRequestHTTPMethod = "POST"
	MessageFederationRequestRoutePath  = "/iimp/api/federation/conversations/{conversationId}/messages"
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
	Attachments []MessageFederationRequestBodyAttachmentsItem `json:"Attachments,omitempty"`

	// A list of message contents for the message, ordered by their version in Ascending Order. The original message sent by the client will have version 1. Each time the message is edited, a new MessageContent object is added to this list with the version number incremented by 1. This allows the server and clients to maintain a history of edits for each message, enabling features such as edit history viewing and audit trails.
	//
	// Required
	//
	// Must be non-empty
	Contents []MessageFederationRequestBodyContentsItem `json:"Contents"`

	// The unique identifier of the conversation that the message belongs to.
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

	// A unique identifier for the message.
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

	// The timestamp when the message was originally sent. Format => RFC3339. This field is included to provide context about when the message was sent, which can be useful for ordering messages and displaying timestamps in the client applications.
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

type MessageFederationRequestBodyAttachmentsItem struct {

	// The MIME type of the attachment (e.g., "image/png", "application/pdf", etc.).
	//
	// Required
	//
	// Must be non-empty
	ContentType string `json:"ContentType"`

	// A hash of the attachment file content (SHA-256 hash) used for integrity verification. The server can use this hash to verify that the attachment file has not been tampered with during storage or transmission.
	//
	// Required
	//
	// Must be non-empty
	FileHash string `json:"FileHash"`

	// A unique identifier for the attachment. Sender's server generates this ID when the attachment is uploaded and returns it to the sender client, which then includes it in the message payload when sending a message with attachments. The server will store the attachment and deliver it to the recipients along with the message content.
	//
	// Required
	//
	// Must be non-empty
	FileId string `json:"FileId"`

	// The original filename of the attachment.
	//
	// Required
	//
	// Must be non-empty
	Filename string `json:"Filename"`

	// The size of the attachment in bytes. The server may enforce a maximum attachment size (1000MB) and reject attachments that exceed this limit.
	//
	// Required
	//
	Size float64 `json:"Size"`
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

	// Encryption details for the recipients of the message. The sender client should not include details for participants of a convo where RemovedAt != nil.
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

	// The timestamp when the message content was created. Format => RFC3339. This field is included to provide context about when the message content was created, which can be useful for ordering messages and displaying timestamps in the client applications.
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

	// The timestamp when the recipient reacted to the message. This field is null if the recipient has not reacted to the message yet. Format => RFC3339. This field is included to provide context about when each reaction was made for the message.
	//
	// Optional
	//
	ReactedAt *string `json:"ReactedAt,omitempty"`

	// An optional reaction from the recipient for the message (e.g., "like", "love", "laugh", "sad", "angry", etc.). This field is included to provide message reaction functionality, allowing recipients to react to messages with predefined reactions. The server will store the reaction and deliver it to the sender and other recipients, allowing them to see the reactions for each message. Emoji-Only field.
	//
	// Optional
	//
	Reaction *string `json:"Reaction,omitempty"`

	// The timestamp when the recipient read the message. This field is null if the recipient has not read the message yet. Format => RFC3339. This field is included to provide read receipt functionality, allowing the sender to know when each recipient has read the message.
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

func (req *MessageFederationRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

func (o *MessageFederationRequestBody) Validate() error {

	for idx, item := range o.Attachments {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("element %d of field 'Attachments' is invalid: %w", idx, err)
		}
	}

	if len(o.Contents) == 0 {
		return fmt.Errorf("field 'Contents' must be non-empty")
	}

	for idx, item := range o.Contents {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("element %d of field 'Contents' is invalid: %w", idx, err)
		}
	}

	if strings.TrimSpace(o.ConversationId) == "" {
		return fmt.Errorf("field 'ConversationId' must be non-empty")
	}

	if strings.TrimSpace(o.MessageId) == "" {
		return fmt.Errorf("field 'MessageId' must be non-empty")
	}

	if strings.TrimSpace(o.SenderUserId) == "" {
		return fmt.Errorf("field 'SenderUserId' must be non-empty")
	}

	if strings.TrimSpace(o.Timestamp) == "" {
		return fmt.Errorf("field 'Timestamp' must be non-empty")
	}

	if len(o.UserSpecificData) == 0 {
		return fmt.Errorf("field 'UserSpecificData' must be non-empty")
	}

	for idx, item := range o.UserSpecificData {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("element %d of field 'UserSpecificData' is invalid: %w", idx, err)
		}
	}

	return nil
}
func (o *MessageFederationRequestBodyAttachmentsItem) Validate() error {

	if strings.TrimSpace(o.ContentType) == "" {
		return fmt.Errorf("field 'ContentType' must be non-empty")
	}

	if strings.TrimSpace(o.FileHash) == "" {
		return fmt.Errorf("field 'FileHash' must be non-empty")
	}

	if strings.TrimSpace(o.FileId) == "" {
		return fmt.Errorf("field 'FileId' must be non-empty")
	}

	if strings.TrimSpace(o.Filename) == "" {
		return fmt.Errorf("field 'Filename' must be non-empty")
	}

	return nil
}
func (o *MessageFederationRequestBodyContentsItem) Validate() error {

	if err := o.MessageContent.Validate(); err != nil {
		return fmt.Errorf("field 'MessageContent' is invalid: %w", err)
	}

	return nil
}
func (o *MessageFederationRequestBodyContentsItemMessageContent) Validate() error {

	if strings.TrimSpace(o.Content) == "" {
		return fmt.Errorf("field 'Content' must be non-empty")
	}

	if len(o.EncryptionData) == 0 {
		return fmt.Errorf("field 'EncryptionData' must be non-empty")
	}

	for idx, item := range o.EncryptionData {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("element %d of field 'EncryptionData' is invalid: %w", idx, err)
		}
	}

	if strings.TrimSpace(o.Nonce) == "" {
		return fmt.Errorf("field 'Nonce' must be non-empty")
	}

	if strings.TrimSpace(o.Timestamp) == "" {
		return fmt.Errorf("field 'Timestamp' must be non-empty")
	}

	return nil
}
func (o *MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem) Validate() error {

	if err := o.Encryption.Validate(); err != nil {
		return fmt.Errorf("field 'Encryption' is invalid: %w", err)
	}

	if strings.TrimSpace(o.RecipientId) == "" {
		return fmt.Errorf("field 'RecipientId' must be non-empty")
	}

	return nil
}
func (o *MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItemEncryption) Validate() error {

	if strings.TrimSpace(o.EncryptedKey) == "" {
		return fmt.Errorf("field 'EncryptedKey' must be non-empty")
	}

	if strings.TrimSpace(o.EncryptedKeyNonce) == "" {
		return fmt.Errorf("field 'EncryptedKeyNonce' must be non-empty")
	}

	if strings.TrimSpace(o.EphemeralPublicKey) == "" {
		return fmt.Errorf("field 'EphemeralPublicKey' must be non-empty")
	}

	if strings.TrimSpace(o.KeyId) == "" {
		return fmt.Errorf("field 'KeyId' must be non-empty")
	}

	return nil
}
func (o *MessageFederationRequestBodyUserSpecificDataItem) Validate() error {

	if strings.TrimSpace(o.RecipientId) == "" {
		return fmt.Errorf("field 'RecipientId' must be non-empty")
	}

	return nil
}

type MessageFederation200Response struct {
}

func NewMessageFederation200Response(resp *http.Response) (MessageFederation200Response, error) {
	defer resp.Body.Close()
	result := MessageFederation200Response{}

	return result, nil
}

type MessageFederation400Response struct {
}

func NewMessageFederation400Response(resp *http.Response) (MessageFederation400Response, error) {
	defer resp.Body.Close()
	result := MessageFederation400Response{}

	return result, nil
}

type MessageFederation401Response struct {
}

func NewMessageFederation401Response(resp *http.Response) (MessageFederation401Response, error) {
	defer resp.Body.Close()
	result := MessageFederation401Response{}

	return result, nil
}

type MessageFederation403Response struct {
}

func NewMessageFederation403Response(resp *http.Response) (MessageFederation403Response, error) {
	defer resp.Body.Close()
	result := MessageFederation403Response{}

	return result, nil
}

type MessageFederation404Response struct {
}

func NewMessageFederation404Response(resp *http.Response) (MessageFederation404Response, error) {
	defer resp.Body.Close()
	result := MessageFederation404Response{}

	return result, nil
}

type MessageFederation500Response struct {
}

func NewMessageFederation500Response(resp *http.Response) (MessageFederation500Response, error) {
	defer resp.Body.Close()
	result := MessageFederation500Response{}

	return result, nil
}

const (
	NewConversationRequestHTTPMethod = "POST"
	NewConversationRequestRoutePath  = "/iimp/api/client/conversations"
)

// Create a new conversation.
type NewConversationRequest struct {

	// Authentication parameters
	Auth NewConversationRequestAuthParams

	// Request body
	Body NewConversationRequestBody
}

type NewConversationRequestBody struct {

	// A name for the conversation, which can be set by the client. This is not used for identification purposes and can be changed by the owner user at any time.
	//
	// Optional
	//
	ConversationName *string `json:"ConversationName,omitempty"`

	// A list of user IDs for the participants to be added to the conversation. For a Direct Conversation, this list must contain exactly 2 user IDs (owner + participant). For a Group Conversation, this list must contain at least 3 user IDs (owner + 2 others).
	//
	// Required
	//
	// Must be non-empty
	ParticipantUserIds []string `json:"ParticipantUserIds"`
}

type NewConversationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *NewConversationRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

func (o *NewConversationRequestBody) Validate() error {

	if len(o.ParticipantUserIds) == 0 {
		return fmt.Errorf("field 'ParticipantUserIds' must be non-empty")
	}

	return nil
}

type NewConversation201Response struct {

	// Response body
	Body NewConversation201ResponseBody
}

type NewConversation201ResponseBodyConversationParticipantsItem struct {

	// The timestamp when the participant joined the conversation. Format => RFC3339.
	//
	// Required
	//
	// Must be non-empty
	JoinedAt string `json:"JoinedAt"`

	// The timestamp when the participant was removed from the conversation. This field is null if the participant is still part of the conversation. Format => RFC3339. A removed participant will not receive new messages in the conversation but can still access the conversation history up until the time they were removed. Owner CANNOT be removed from the conversation.
	//
	// Optional
	//
	RemovedAt *string `json:"RemovedAt,omitempty"`

	// This is the display name of the participant at the time they joined the conversation. This is not updated if the user changes their display name later. This field is included to provide context about the participant's identity within the conversation, even if their global display name changes over time. During federation, the owner's server contacts the participant's server to fetch the current display name of the participant, which is then stored as UserDisplayName in the conversation participant list. This allows the conversation to maintain a consistent display name for the participant, even if they change their display name globally on their server.
	//
	// Required
	//
	// Must be non-empty
	UserDisplayName string `json:"UserDisplayName"`

	// User ID of the participant. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

type NewConversation201ResponseBodyConversation struct {

	// A unique identifier for the conversation.
	//
	// Required
	//
	// Must be non-empty
	ConversationId string `json:"ConversationId"`

	// An optional name for the conversation, which can be set by the client. This is not used for identification purposes and can be changed by the owner user at any time.
	//
	// Optional
	//
	ConversationName *string `json:"ConversationName,omitempty"`

	// The user ID of the owner of the conversation. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	ConversationOwnerId string `json:"ConversationOwnerId"`

	// The timestamp when the conversation was created. Format => RFC3339.
	//
	// Required
	//
	// Must be non-empty
	CreatedAt string `json:"CreatedAt"`

	// A flag indicating whether the conversation is a Direct Message (DM) or a Group Conversation. A Direct Message conversation has exactly 2 participants (including the owner), while a Group Conversation has more than 2 participants.
	//
	// Required
	//
	IsDM bool `json:"IsDM"`

	// A list of participants in the conversation. The owner of the conversation is also included in this list. Participants can be added or removed by the owner user. Contains at least 2 participants (including the owner) for a Direct Conversation and >2 participants for a Group Conversation.
	//
	// Required
	//
	// Must be non-empty
	Participants []NewConversation201ResponseBodyConversationParticipantsItem `json:"Participants"`
}

type NewConversation201ResponseBody struct {

	// Details of the created conversation.
	//
	// Required
	//
	Conversation NewConversation201ResponseBodyConversation `json:"Conversation"`
}

func NewNewConversation201Response(resp *http.Response) (NewConversation201Response, error) {
	defer resp.Body.Close()
	result := NewConversation201Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type NewConversation400Response struct {
}

func NewNewConversation400Response(resp *http.Response) (NewConversation400Response, error) {
	defer resp.Body.Close()
	result := NewConversation400Response{}

	return result, nil
}

type NewConversation401Response struct {
}

func NewNewConversation401Response(resp *http.Response) (NewConversation401Response, error) {
	defer resp.Body.Close()
	result := NewConversation401Response{}

	return result, nil
}

type NewConversation403Response struct {
}

func NewNewConversation403Response(resp *http.Response) (NewConversation403Response, error) {
	defer resp.Body.Close()
	result := NewConversation403Response{}

	return result, nil
}

type NewConversation404Response struct {
}

func NewNewConversation404Response(resp *http.Response) (NewConversation404Response, error) {
	defer resp.Body.Close()
	result := NewConversation404Response{}

	return result, nil
}

type NewConversation500Response struct {
}

func NewNewConversation500Response(resp *http.Response) (NewConversation500Response, error) {
	defer resp.Body.Close()
	result := NewConversation500Response{}

	return result, nil
}

const (
	NewMessageRequestHTTPMethod = "POST"
	NewMessageRequestRoutePath  = "/iimp/api/client/conversations/{conversationId}/messages"
)

// Send a new message in a conversation.
type NewMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation to send the message in.
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
	Attachments []NewMessageRequestBodyAttachmentsItem `json:"Attachments,omitempty"`

	// The content of the message to be sent in the conversation. The content should be encrypted using an AES key, and the AES key should be encrypted for each recipient using their respective public keys. The server will store the encrypted message content and the encrypted keys for each recipient, allowing the recipients to decrypt the AES key using their private keys and then use it to decrypt the message content.
	//
	// Required
	//
	MessageContent NewMessageRequestBodyMessageContent `json:"MessageContent"`
}

type NewMessageRequestBodyAttachmentsItem struct {

	// The MIME type of the attachment (e.g., "image/png", "application/pdf", etc.).
	//
	// Required
	//
	// Must be non-empty
	ContentType string `json:"ContentType"`

	// A hash of the attachment file content (SHA-256 hash) used for integrity verification. The server can use this hash to verify that the attachment file has not been tampered with during storage or transmission.
	//
	// Required
	//
	// Must be non-empty
	FileHash string `json:"FileHash"`

	// A unique identifier for the attachment. Sender's server generates this ID when the attachment is uploaded and returns it to the sender client, which then includes it in the message payload when sending a message with attachments. The server will store the attachment and deliver it to the recipients along with the message content.
	//
	// Required
	//
	// Must be non-empty
	FileId string `json:"FileId"`

	// The original filename of the attachment.
	//
	// Required
	//
	// Must be non-empty
	Filename string `json:"Filename"`

	// The size of the attachment in bytes. The server may enforce a maximum attachment size (1000MB) and reject attachments that exceed this limit.
	//
	// Required
	//
	Size float64 `json:"Size"`
}

type NewMessageRequestBodyMessageContent struct {

	// The content of the message to be sent in the conversation. The content should be encrypted using an AES key, and the AES key should be encrypted for each recipient using their respective public keys. The server will store the encrypted message content and the encrypted keys for each recipient, allowing the recipients to decrypt the AES key using their private keys and then use it to decrypt the message content.
	//
	// Required
	//
	// Must be non-empty
	Content string `json:"Content"`

	// Encryption details for the recipients of the message. The sender client should not include details for participants of a convo where RemovedAt != nil.
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

	// The timestamp when the message content was created. Format => RFC3339. This field is included to provide context about when the message content was created, which can be useful for ordering messages and displaying timestamps in the client applications.
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

func (req *NewMessageRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

func (o *NewMessageRequestBody) Validate() error {

	for idx, item := range o.Attachments {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("element %d of field 'Attachments' is invalid: %w", idx, err)
		}
	}

	if err := o.MessageContent.Validate(); err != nil {
		return fmt.Errorf("field 'MessageContent' is invalid: %w", err)
	}

	return nil
}
func (o *NewMessageRequestBodyAttachmentsItem) Validate() error {

	if strings.TrimSpace(o.ContentType) == "" {
		return fmt.Errorf("field 'ContentType' must be non-empty")
	}

	if strings.TrimSpace(o.FileHash) == "" {
		return fmt.Errorf("field 'FileHash' must be non-empty")
	}

	if strings.TrimSpace(o.FileId) == "" {
		return fmt.Errorf("field 'FileId' must be non-empty")
	}

	if strings.TrimSpace(o.Filename) == "" {
		return fmt.Errorf("field 'Filename' must be non-empty")
	}

	return nil
}
func (o *NewMessageRequestBodyMessageContent) Validate() error {

	if strings.TrimSpace(o.Content) == "" {
		return fmt.Errorf("field 'Content' must be non-empty")
	}

	if len(o.EncryptionData) == 0 {
		return fmt.Errorf("field 'EncryptionData' must be non-empty")
	}

	for idx, item := range o.EncryptionData {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("element %d of field 'EncryptionData' is invalid: %w", idx, err)
		}
	}

	if strings.TrimSpace(o.Nonce) == "" {
		return fmt.Errorf("field 'Nonce' must be non-empty")
	}

	if strings.TrimSpace(o.Timestamp) == "" {
		return fmt.Errorf("field 'Timestamp' must be non-empty")
	}

	return nil
}
func (o *NewMessageRequestBodyMessageContentEncryptionDataItem) Validate() error {

	if err := o.Encryption.Validate(); err != nil {
		return fmt.Errorf("field 'Encryption' is invalid: %w", err)
	}

	if strings.TrimSpace(o.RecipientId) == "" {
		return fmt.Errorf("field 'RecipientId' must be non-empty")
	}

	return nil
}
func (o *NewMessageRequestBodyMessageContentEncryptionDataItemEncryption) Validate() error {

	if strings.TrimSpace(o.EncryptedKey) == "" {
		return fmt.Errorf("field 'EncryptedKey' must be non-empty")
	}

	if strings.TrimSpace(o.EncryptedKeyNonce) == "" {
		return fmt.Errorf("field 'EncryptedKeyNonce' must be non-empty")
	}

	if strings.TrimSpace(o.EphemeralPublicKey) == "" {
		return fmt.Errorf("field 'EphemeralPublicKey' must be non-empty")
	}

	if strings.TrimSpace(o.KeyId) == "" {
		return fmt.Errorf("field 'KeyId' must be non-empty")
	}

	return nil
}

type NewMessage201Response struct {
}

func NewNewMessage201Response(resp *http.Response) (NewMessage201Response, error) {
	defer resp.Body.Close()
	result := NewMessage201Response{}

	return result, nil
}

type NewMessage400Response struct {
}

func NewNewMessage400Response(resp *http.Response) (NewMessage400Response, error) {
	defer resp.Body.Close()
	result := NewMessage400Response{}

	return result, nil
}

type NewMessage401Response struct {
}

func NewNewMessage401Response(resp *http.Response) (NewMessage401Response, error) {
	defer resp.Body.Close()
	result := NewMessage401Response{}

	return result, nil
}

type NewMessage403Response struct {
}

func NewNewMessage403Response(resp *http.Response) (NewMessage403Response, error) {
	defer resp.Body.Close()
	result := NewMessage403Response{}

	return result, nil
}

type NewMessage404Response struct {
}

func NewNewMessage404Response(resp *http.Response) (NewMessage404Response, error) {
	defer resp.Body.Close()
	result := NewMessage404Response{}

	return result, nil
}

type NewMessage500Response struct {
}

func NewNewMessage500Response(resp *http.Response) (NewMessage500Response, error) {
	defer resp.Body.Close()
	result := NewMessage500Response{}

	return result, nil
}

const (
	PullUserEventsRequestHTTPMethod = "GET"
	PullUserEventsRequestRoutePath  = "/iimp/api/client/events"
)

// Fetch a list of events for the authenticated user.
type PullUserEventsRequest struct {

	// Source: query parameter "cursor"
	//

	// A cursor (for this use case, MongoDB's ObjectID) for pagination. The server will return events starting from this cursor. If not provided, the server will return all available events starting from the oldest event in the system. The response will include a next_cursor field that can be used to fetch the next page of results.
	//
	// Optional
	Cursor *string

	// Source: query parameter "limit"
	//

	// The maximum number of events to return in the response. If not provided, the server will use a default limit (50). The server may enforce a maximum limit (100) to prevent excessively large responses.
	//
	// Optional
	Limit *float64

	// Authentication parameters
	Auth PullUserEventsRequestAuthParams
}

type PullUserEventsRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *PullUserEventsRequest) Validate() error {

	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

type PullUserEvents200Response struct {

	// Response body
	Body PullUserEvents200ResponseBody
}

type PullUserEvents200ResponseBodyEventsItem struct {

	// The timestamp when the event was created. Format => RFC3339.
	//
	// Required
	//
	// Must be non-empty
	CreatedAt string `json:"CreatedAt"`

	// A unique identifier for the event (Monotonically increasing per-user sequence number).
	//
	// Required
	//
	EventId string `json:"EventId"`

	// The type of the event (e.g., "message_received", "conversation_created", etc.). This field can be used by the client to determine how to process the event. For a full list of event types and their corresponding payload structures, refer to the IIMP Client Events documentation [here](https://github.com/iim-protocol/iimp/tree/main/Events.md).
	//
	// Required
	//
	// Must be non-empty
	EventType string `json:"EventType"`

	// An optional field containing additional data related to the event. The structure of this object can vary depending on the event type and must conform to the IIMP Client Events documentation. Clients should be designed to handle different payload structures based on the event type.
	//
	// Optional
	//
	Payload *map[string]any `json:"Payload,omitempty"`

	// User ID of the user to whom the event belongs. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

type PullUserEvents200ResponseBody struct {

	// A list of events for the authenticated user, if any available. The events are ordered by their EventId in Ascending Order. The server may return up to 'limit' events in the response. If there are more events available beyond the returned list, a 'next_cursor' field will be included in the response, which can be used to fetch the next page of results.
	//
	// Required
	//
	Events []PullUserEvents200ResponseBodyEventsItem `json:"Events"`

	// A cursor for the next page of results, if available. This field will be included in the response if there are more events available beyond the returned list.
	//
	// Optional
	//
	NextCursor *string `json:"NextCursor,omitempty"`
}

func NewPullUserEvents200Response(resp *http.Response) (PullUserEvents200Response, error) {
	defer resp.Body.Close()
	result := PullUserEvents200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type PullUserEvents400Response struct {
}

func NewPullUserEvents400Response(resp *http.Response) (PullUserEvents400Response, error) {
	defer resp.Body.Close()
	result := PullUserEvents400Response{}

	return result, nil
}

type PullUserEvents401Response struct {
}

func NewPullUserEvents401Response(resp *http.Response) (PullUserEvents401Response, error) {
	defer resp.Body.Close()
	result := PullUserEvents401Response{}

	return result, nil
}

type PullUserEvents500Response struct {
}

func NewPullUserEvents500Response(resp *http.Response) (PullUserEvents500Response, error) {
	defer resp.Body.Close()
	result := PullUserEvents500Response{}

	return result, nil
}

const (
	ReactToMessageRequestHTTPMethod = "POST"
	ReactToMessageRequestRoutePath  = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/react"
)

// React to a message in a conversation.
type ReactToMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message to react to.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth ReactToMessageRequestAuthParams

	// Request body
	Body ReactToMessageRequestBody
}

type ReactToMessageRequestBody struct {

	// A reaction from the recipient of a message (e.g., "like", "love", "laugh", "sad", "angry", etc.). Emoji-Only field. Null to remove reaction.
	//
	// Optional
	//
	Reaction *string `json:"Reaction,omitempty"`
}

type ReactToMessageRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *ReactToMessageRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

func (o *ReactToMessageRequestBody) Validate() error {

	return nil
}

type ReactToMessage200Response struct {
}

func NewReactToMessage200Response(resp *http.Response) (ReactToMessage200Response, error) {
	defer resp.Body.Close()
	result := ReactToMessage200Response{}

	return result, nil
}

type ReactToMessage400Response struct {
}

func NewReactToMessage400Response(resp *http.Response) (ReactToMessage400Response, error) {
	defer resp.Body.Close()
	result := ReactToMessage400Response{}

	return result, nil
}

type ReactToMessage401Response struct {
}

func NewReactToMessage401Response(resp *http.Response) (ReactToMessage401Response, error) {
	defer resp.Body.Close()
	result := ReactToMessage401Response{}

	return result, nil
}

type ReactToMessage403Response struct {
}

func NewReactToMessage403Response(resp *http.Response) (ReactToMessage403Response, error) {
	defer resp.Body.Close()
	result := ReactToMessage403Response{}

	return result, nil
}

type ReactToMessage404Response struct {
}

func NewReactToMessage404Response(resp *http.Response) (ReactToMessage404Response, error) {
	defer resp.Body.Close()
	result := ReactToMessage404Response{}

	return result, nil
}

type ReactToMessage500Response struct {
}

func NewReactToMessage500Response(resp *http.Response) (ReactToMessage500Response, error) {
	defer resp.Body.Close()
	result := ReactToMessage500Response{}

	return result, nil
}

const (
	ReadMessageRequestHTTPMethod = "POST"
	ReadMessageRequestRoutePath  = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/read"
)

// Mark a message as read by the authenticated user.
type ReadMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message to mark as read.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth ReadMessageRequestAuthParams
}

type ReadMessageRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *ReadMessageRequest) Validate() error {

	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

type ReadMessage200Response struct {
}

func NewReadMessage200Response(resp *http.Response) (ReadMessage200Response, error) {
	defer resp.Body.Close()
	result := ReadMessage200Response{}

	return result, nil
}

type ReadMessage400Response struct {
}

func NewReadMessage400Response(resp *http.Response) (ReadMessage400Response, error) {
	defer resp.Body.Close()
	result := ReadMessage400Response{}

	return result, nil
}

type ReadMessage401Response struct {
}

func NewReadMessage401Response(resp *http.Response) (ReadMessage401Response, error) {
	defer resp.Body.Close()
	result := ReadMessage401Response{}

	return result, nil
}

type ReadMessage403Response struct {
}

func NewReadMessage403Response(resp *http.Response) (ReadMessage403Response, error) {
	defer resp.Body.Close()
	result := ReadMessage403Response{}

	return result, nil
}

type ReadMessage404Response struct {
}

func NewReadMessage404Response(resp *http.Response) (ReadMessage404Response, error) {
	defer resp.Body.Close()
	result := ReadMessage404Response{}

	return result, nil
}

type ReadMessage500Response struct {
}

func NewReadMessage500Response(resp *http.Response) (ReadMessage500Response, error) {
	defer resp.Body.Close()
	result := ReadMessage500Response{}

	return result, nil
}

const (
	RedactMessageRequestHTTPMethod = "POST"
	RedactMessageRequestRoutePath  = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/redact"
)

// Redact a message in a conversation. If this conversation is a Direct Conversation, only the sender of the message can redact it. If this conversation is a Group Conversation, only the sender of the message or the owner of the conversation can redact it.
type RedactMessageRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation that the message belongs to.
	//
	// Required
	ConversationId string

	// Source: path parameter "{messageId}"
	//

	// The unique identifier of the message to redact.
	//
	// Required
	MessageId string

	// Authentication parameters
	Auth RedactMessageRequestAuthParams
}

type RedactMessageRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *RedactMessageRequest) Validate() error {

	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

type RedactMessage200Response struct {
}

func NewRedactMessage200Response(resp *http.Response) (RedactMessage200Response, error) {
	defer resp.Body.Close()
	result := RedactMessage200Response{}

	return result, nil
}

type RedactMessage400Response struct {
}

func NewRedactMessage400Response(resp *http.Response) (RedactMessage400Response, error) {
	defer resp.Body.Close()
	result := RedactMessage400Response{}

	return result, nil
}

type RedactMessage401Response struct {
}

func NewRedactMessage401Response(resp *http.Response) (RedactMessage401Response, error) {
	defer resp.Body.Close()
	result := RedactMessage401Response{}

	return result, nil
}

type RedactMessage403Response struct {
}

func NewRedactMessage403Response(resp *http.Response) (RedactMessage403Response, error) {
	defer resp.Body.Close()
	result := RedactMessage403Response{}

	return result, nil
}

type RedactMessage404Response struct {
}

func NewRedactMessage404Response(resp *http.Response) (RedactMessage404Response, error) {
	defer resp.Body.Close()
	result := RedactMessage404Response{}

	return result, nil
}

type RedactMessage500Response struct {
}

func NewRedactMessage500Response(resp *http.Response) (RedactMessage500Response, error) {
	defer resp.Body.Close()
	result := RedactMessage500Response{}

	return result, nil
}

const (
	RefreshSessionRequestHTTPMethod = "POST"
	RefreshSessionRequestRoutePath  = "/iimp/api/client/refresh-session"
)

// Refresh the session token.
type RefreshSessionRequest struct {

	// Request body
	Body RefreshSessionRequestBody
}

type RefreshSessionRequestBody struct {

	// A token used to refresh the session token when it expires.
	//
	// Required
	//
	// Must be non-empty
	RefreshToken string `json:"RefreshToken"`
}

func (req *RefreshSessionRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	return nil
}

func (o *RefreshSessionRequestBody) Validate() error {

	if strings.TrimSpace(o.RefreshToken) == "" {
		return fmt.Errorf("field 'RefreshToken' must be non-empty")
	}

	return nil
}

type RefreshSession200Response struct {

	// Response body
	Body RefreshSession200ResponseBody
}

type RefreshSession200ResponseBody struct {

	// A new token used to refresh the session token when it expires. Previous refresh tokens are invalidated when a new refresh token is issued.
	//
	// Required
	//
	// Must be non-empty
	RefreshToken string `json:"RefreshToken"`

	// The timestamp of when the refresh token expires. Format => RFC3339
	//
	// Required
	//
	RefreshTokenExpiry string `json:"RefreshTokenExpiry"`

	// A new token used to authenticate the client session. This token must be included in the header of subsequent requests to access protected resources.
	//
	// Required
	//
	// Must be non-empty
	SessionToken string `json:"SessionToken"`

	// The timestamp of when the session token expires. Format => RFC3339
	//
	// Required
	//
	SessionTokenExpiry string `json:"SessionTokenExpiry"`
}

func NewRefreshSession200Response(resp *http.Response) (RefreshSession200Response, error) {
	defer resp.Body.Close()
	result := RefreshSession200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type RefreshSession400Response struct {
}

func NewRefreshSession400Response(resp *http.Response) (RefreshSession400Response, error) {
	defer resp.Body.Close()
	result := RefreshSession400Response{}

	return result, nil
}

type RefreshSession401Response struct {
}

func NewRefreshSession401Response(resp *http.Response) (RefreshSession401Response, error) {
	defer resp.Body.Close()
	result := RefreshSession401Response{}

	return result, nil
}

type RefreshSession500Response struct {
}

func NewRefreshSession500Response(resp *http.Response) (RefreshSession500Response, error) {
	defer resp.Body.Close()
	result := RefreshSession500Response{}

	return result, nil
}

const (
	RequestResetPasswordRequestHTTPMethod = "POST"
	RequestResetPasswordRequestRoutePath  = "/iimp/api/client/request-reset-password"
)

// Request a password reset for the user account.
type RequestResetPasswordRequest struct {

	// Request body
	Body RequestResetPasswordRequestBody
}

type RequestResetPasswordRequestBody struct {

	// User ID for the account.
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func (req *RequestResetPasswordRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	return nil
}

func (o *RequestResetPasswordRequestBody) Validate() error {

	if strings.TrimSpace(o.UserId) == "" {
		return fmt.Errorf("field 'UserId' must be non-empty")
	}

	return nil
}

type RequestResetPassword200Response struct {
}

func NewRequestResetPassword200Response(resp *http.Response) (RequestResetPassword200Response, error) {
	defer resp.Body.Close()
	result := RequestResetPassword200Response{}

	return result, nil
}

type RequestResetPassword400Response struct {
}

func NewRequestResetPassword400Response(resp *http.Response) (RequestResetPassword400Response, error) {
	defer resp.Body.Close()
	result := RequestResetPassword400Response{}

	return result, nil
}

type RequestResetPassword500Response struct {
}

func NewRequestResetPassword500Response(resp *http.Response) (RequestResetPassword500Response, error) {
	defer resp.Body.Close()
	result := RequestResetPassword500Response{}

	return result, nil
}

const (
	ResetPasswordRequestHTTPMethod = "POST"
	ResetPasswordRequestRoutePath  = "/iimp/api/client/reset-password"
)

// Reset the password for the user account.
type ResetPasswordRequest struct {

	// Request body
	Body ResetPasswordRequestBody
}

type ResetPasswordRequestBody struct {

	// New password for the account.
	//
	// Required
	//
	// Must be non-empty
	NewPassword string `json:"NewPassword"`

	// A token sent to the user's email address as part of the password reset process. This token is used to verify the password reset request.
	//
	// Required
	//
	// Must be non-empty
	ResetToken string `json:"ResetToken"`

	// User ID for the account.
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func (req *ResetPasswordRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	return nil
}

func (o *ResetPasswordRequestBody) Validate() error {

	if strings.TrimSpace(o.NewPassword) == "" {
		return fmt.Errorf("field 'NewPassword' must be non-empty")
	}

	if strings.TrimSpace(o.ResetToken) == "" {
		return fmt.Errorf("field 'ResetToken' must be non-empty")
	}

	if strings.TrimSpace(o.UserId) == "" {
		return fmt.Errorf("field 'UserId' must be non-empty")
	}

	return nil
}

type ResetPassword200Response struct {
}

func NewResetPassword200Response(resp *http.Response) (ResetPassword200Response, error) {
	defer resp.Body.Close()
	result := ResetPassword200Response{}

	return result, nil
}

type ResetPassword401Response struct {
}

func NewResetPassword401Response(resp *http.Response) (ResetPassword401Response, error) {
	defer resp.Body.Close()
	result := ResetPassword401Response{}

	return result, nil
}

type ResetPassword500Response struct {
}

func NewResetPassword500Response(resp *http.Response) (ResetPassword500Response, error) {
	defer resp.Body.Close()
	result := ResetPassword500Response{}

	return result, nil
}

const (
	SignUpRequestHTTPMethod = "POST"
	SignUpRequestRoutePath  = "/iimp/api/client/signup"
)

// Register a new user account with the IIMP service.
type SignUpRequest struct {

	// Request body
	Body SignUpRequestBody
}

type SignUpRequestBody struct {

	// Display name for the user.
	//
	// Required
	//
	// Must be non-empty
	DisplayName string `json:"DisplayName"`

	// Email address for the new account. This can be same as the user ID or a different email address. The email address will be used for account recovery.
	//
	// Required
	//
	// Must be non-empty
	Email string `json:"Email"`

	// Password for the new account.
	//
	// Required
	//
	// Must be non-empty
	Password string `json:"Password"`

	// Desired user ID for the new account. (localpart@domain). Domain must be the same as the server's domain.
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func (req *SignUpRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	return nil
}

func (o *SignUpRequestBody) Validate() error {

	if strings.TrimSpace(o.DisplayName) == "" {
		return fmt.Errorf("field 'DisplayName' must be non-empty")
	}

	if strings.TrimSpace(o.Email) == "" {
		return fmt.Errorf("field 'Email' must be non-empty")
	}

	if strings.TrimSpace(o.Password) == "" {
		return fmt.Errorf("field 'Password' must be non-empty")
	}

	if strings.TrimSpace(o.UserId) == "" {
		return fmt.Errorf("field 'UserId' must be non-empty")
	}

	return nil
}

type SignUp201Response struct {
}

func NewSignUp201Response(resp *http.Response) (SignUp201Response, error) {
	defer resp.Body.Close()
	result := SignUp201Response{}

	return result, nil
}

type SignUp400Response struct {
}

func NewSignUp400Response(resp *http.Response) (SignUp400Response, error) {
	defer resp.Body.Close()
	result := SignUp400Response{}

	return result, nil
}

type SignUp403Response struct {
}

func NewSignUp403Response(resp *http.Response) (SignUp403Response, error) {
	defer resp.Body.Close()
	result := SignUp403Response{}

	return result, nil
}

type SignUp409Response struct {
}

func NewSignUp409Response(resp *http.Response) (SignUp409Response, error) {
	defer resp.Body.Close()
	result := SignUp409Response{}

	return result, nil
}

type SignUp500Response struct {
}

func NewSignUp500Response(resp *http.Response) (SignUp500Response, error) {
	defer resp.Body.Close()
	result := SignUp500Response{}

	return result, nil
}

const (
	UpdateConversationRequestHTTPMethod = "PUT"
	UpdateConversationRequestRoutePath  = "/iimp/api/client/conversations/{conversationId}"
)

// Update an existing conversation. Only for Group Conversations, Direct Conversations cannot be updated.
type UpdateConversationRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation to update.
	//
	// Required
	ConversationId string

	// Authentication parameters
	Auth UpdateConversationRequestAuthParams

	// Request body
	Body UpdateConversationRequestBody
}

type UpdateConversationRequestBody struct {

	// An updated name for the conversation, which can be set by the client. This is not used for identification purposes and can be changed by the owner user at any time.
	//
	// Optional
	//
	ConversationName *string `json:"ConversationName,omitempty"`

	// A list of user IDs for the participants to be added to the conversation.
	//
	// Optional
	//
	ParticipantUserIdsToAdd []string `json:"ParticipantUserIdsToAdd,omitempty"`

	// A list of user IDs for the participants to be removed from the conversation. The owner user cannot be removed from the conversation and should not be included in this list.
	//
	// Optional
	//
	ParticipantUserIdsToRemove []string `json:"ParticipantUserIdsToRemove,omitempty"`
}

type UpdateConversationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func (req *UpdateConversationRequest) Validate() error {

	if err := req.Body.Validate(); err != nil {
		return err
	}
	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
}

func (o *UpdateConversationRequestBody) Validate() error {

	return nil
}

type UpdateConversation200Response struct {

	// Response body
	Body UpdateConversation200ResponseBody
}

type UpdateConversation200ResponseBodyConversationParticipantsItem struct {

	// The timestamp when the participant joined the conversation. Format => RFC3339.
	//
	// Required
	//
	// Must be non-empty
	JoinedAt string `json:"JoinedAt"`

	// The timestamp when the participant was removed from the conversation. This field is null if the participant is still part of the conversation. Format => RFC3339. A removed participant will not receive new messages in the conversation but can still access the conversation history up until the time they were removed. Owner CANNOT be removed from the conversation.
	//
	// Optional
	//
	RemovedAt *string `json:"RemovedAt,omitempty"`

	// This is the display name of the participant at the time they joined the conversation. This is not updated if the user changes their display name later. This field is included to provide context about the participant's identity within the conversation, even if their global display name changes over time. During federation, the owner's server contacts the participant's server to fetch the current display name of the participant, which is then stored as UserDisplayName in the conversation participant list. This allows the conversation to maintain a consistent display name for the participant, even if they change their display name globally on their server.
	//
	// Required
	//
	// Must be non-empty
	UserDisplayName string `json:"UserDisplayName"`

	// User ID of the participant. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

type UpdateConversation200ResponseBodyConversation struct {

	// A unique identifier for the conversation.
	//
	// Required
	//
	// Must be non-empty
	ConversationId string `json:"ConversationId"`

	// An optional name for the conversation, which can be set by the client. This is not used for identification purposes and can be changed by the owner user at any time.
	//
	// Optional
	//
	ConversationName *string `json:"ConversationName,omitempty"`

	// The user ID of the owner of the conversation. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	ConversationOwnerId string `json:"ConversationOwnerId"`

	// The timestamp when the conversation was created. Format => RFC3339.
	//
	// Required
	//
	// Must be non-empty
	CreatedAt string `json:"CreatedAt"`

	// A flag indicating whether the conversation is a Direct Message (DM) or a Group Conversation. A Direct Message conversation has exactly 2 participants (including the owner), while a Group Conversation has more than 2 participants.
	//
	// Required
	//
	IsDM bool `json:"IsDM"`

	// A list of participants in the conversation. The owner of the conversation is also included in this list. Participants can be added or removed by the owner user. Contains at least 2 participants (including the owner) for a Direct Conversation and >2 participants for a Group Conversation.
	//
	// Required
	//
	// Must be non-empty
	Participants []UpdateConversation200ResponseBodyConversationParticipantsItem `json:"Participants"`
}

type UpdateConversation200ResponseBody struct {

	// Details of the updated conversation.
	//
	// Required
	//
	Conversation UpdateConversation200ResponseBodyConversation `json:"Conversation"`
}

func NewUpdateConversation200Response(resp *http.Response) (UpdateConversation200Response, error) {
	defer resp.Body.Close()
	result := UpdateConversation200Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type UpdateConversation400Response struct {
}

func NewUpdateConversation400Response(resp *http.Response) (UpdateConversation400Response, error) {
	defer resp.Body.Close()
	result := UpdateConversation400Response{}

	return result, nil
}

type UpdateConversation401Response struct {
}

func NewUpdateConversation401Response(resp *http.Response) (UpdateConversation401Response, error) {
	defer resp.Body.Close()
	result := UpdateConversation401Response{}

	return result, nil
}

type UpdateConversation403Response struct {
}

func NewUpdateConversation403Response(resp *http.Response) (UpdateConversation403Response, error) {
	defer resp.Body.Close()
	result := UpdateConversation403Response{}

	return result, nil
}

type UpdateConversation404Response struct {
}

func NewUpdateConversation404Response(resp *http.Response) (UpdateConversation404Response, error) {
	defer resp.Body.Close()
	result := UpdateConversation404Response{}

	return result, nil
}

type UpdateConversation500Response struct {
}

func NewUpdateConversation500Response(resp *http.Response) (UpdateConversation500Response, error) {
	defer resp.Body.Close()
	result := UpdateConversation500Response{}

	return result, nil
}

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

func (req *UploadAttachmentRequest) Validate() error {

	// Authentication parameters validation

	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		return fmt.Errorf("missing required authentication parameter: Authorization")
	}

	return nil
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

func NewUploadAttachment201Response(resp *http.Response) (UploadAttachment201Response, error) {
	defer resp.Body.Close()
	result := UploadAttachment201Response{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result.Body); err != nil {
		return result, err
	}

	return result, nil
}

type UploadAttachment400Response struct {
}

func NewUploadAttachment400Response(resp *http.Response) (UploadAttachment400Response, error) {
	defer resp.Body.Close()
	result := UploadAttachment400Response{}

	return result, nil
}

type UploadAttachment401Response struct {
}

func NewUploadAttachment401Response(resp *http.Response) (UploadAttachment401Response, error) {
	defer resp.Body.Close()
	result := UploadAttachment401Response{}

	return result, nil
}

type UploadAttachment403Response struct {
}

func NewUploadAttachment403Response(resp *http.Response) (UploadAttachment403Response, error) {
	defer resp.Body.Close()
	result := UploadAttachment403Response{}

	return result, nil
}

type UploadAttachment404Response struct {
}

func NewUploadAttachment404Response(resp *http.Response) (UploadAttachment404Response, error) {
	defer resp.Body.Close()
	result := UploadAttachment404Response{}

	return result, nil
}

type UploadAttachment413Response struct {
}

func NewUploadAttachment413Response(resp *http.Response) (UploadAttachment413Response, error) {
	defer resp.Body.Close()
	result := UploadAttachment413Response{}

	return result, nil
}

type UploadAttachment500Response struct {
}

func NewUploadAttachment500Response(resp *http.Response) (UploadAttachment500Response, error) {
	defer resp.Body.Close()
	result := UploadAttachment500Response{}

	return result, nil
}
