package dbmodels

import "go.mongodb.org/mongo-driver/v2/bson"

const ConversationsCollection = "conversations"

type Conversation struct {
	Id           bson.ObjectID             `bson:"_id,omitempty"`
	Name         string                    `bson:"name,omitempty"`
	OwnerId      string                    `bson:"owner_id"`     // User ID of the conversation owner (localpart@domain)
	IsDM         bool                      `bson:"is_dm"`        // Indicates if the conversation is a direct message (DM) or a group chat
	Participants []ConversationParticipant `bson:"participants"` // List of participants in the conversation
}

type ConversationParticipant struct {
	UserId          string         `bson:"user_id"` // User ID of the participant (localpart@domain)
	UserDisplayName string         `bson:"user_display_name"`
	JoinedAt        bson.DateTime  `bson:"joined_at"`            // Timestamp of when the participant joined the conversation
	RemovedAt       *bson.DateTime `bson:"removed_at,omitempty"` // Timestamp of when the participant was removed from the conversation (null if still a participant)
}
