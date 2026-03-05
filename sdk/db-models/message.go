package dbmodels

import "go.mongodb.org/mongo-driver/v2/bson"

const MessagesCollection = "messages"

type Message struct {
	Id               bson.ObjectID                 `bson:"_id,omitempty"`
	ConversationId   bson.ObjectID                 `bson:"conversation_id"`    // ID of the conversation this message belongs to
	SenderUserId     string                        `bson:"sender_user_id"`     // User ID of the sender (localpart@domain)
	IsRedacted       bool                          `bson:"is_redacted"`        // Whether the message has been redacted
	Attachments      []Attachment                  `bson:"attachments"`        // List of attachments associated with the message
	Contents         []MessageContentItem          `bson:"contents"`           // List of content items in the message (text, files, etc.)
	UserSpecificData []MessageUserSpecificDataItem `bson:"user_specific_data"` // List of user-specific data items (e.g., read receipts, reactions)
}

type Attachment struct {
	FileId      bson.ObjectID `bson:"file_id"`      // ID of the file in GridFS
	Filename    string        `bson:"filename"`     // Original filename of the attachment
	ContentType string        `bson:"content_type"` // MIME type of the attachment
	Size        int64         `bson:"size"`         // Size of the attachment in bytes
	FileHash    string        `bson:"file_hash"`    // SHA256 Hash of the file contents for integrity verification
}

type MessageUserSpecificDataItem struct {
	RecipientId string         `bson:"recipient_id"`         // User ID of the recipient this data item is specific to (localpart@domain)
	ReadAt      *bson.DateTime `bson:"read_at,omitempty"`    // Timestamp of when the message was read by the recipient (if applicable)
	Reaction    *string        `bson:"reaction,omitempty"`   // Optional reaction (e.g., emoji) added by the recipient
	ReactedAt   *bson.DateTime `bson:"reacted_at,omitempty"` // Timestamp of when the reaction was added (if applicable)
}

type MessageContentItem struct {
	Version        int        `bson:"version"` // Version number of the content item format
	MessageContent MsgContent `bson:"content"` // The actual content of the message (text, file reference, etc.)
}

type MsgContent struct {
	Content        string                  `bson:"content"`         // The actual encrypted text content of the message
	Nonce          string                  `bson:"nonce"`           // Nonce used for encrypting the content
	EncryptionData []MessageEncryptionData `bson:"encryption_data"` // Metadata about the encryption, per recipient
	Timestamp      bson.DateTime           `bson:"timestamp"`       // Timestamp of when the message content was created
}

type MessageEncryptionData struct {
	RecipientId string            `bson:"recipient_id"` // User ID of the recipient this encryption data is for (localpart@domain)
	Encryption  MessageEncryption `bson:"encryption"`   // Encryption details for this recipient
}

// X25519 + HKDF-based encryption metadata for a single recipient
type MessageEncryption struct {
	KeyId              string `bson:"key_id"`               // Identifier for the encryption key used
	EncryptedKey       string `bson:"encrypted_key"`        // The symmetric key encrypted with the recipient's public key
	EphemeralPublicKey string `bson:"ephemeral_public_key"` // The ephemeral public key used for encryption
	EncryptedKeyNonce  string `bson:"encrypted_key_nonce"`  // Nonce used for encrypting the symmetric key
}
