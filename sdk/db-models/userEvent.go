package dbmodels

import "go.mongodb.org/mongo-driver/v2/bson"

const UserEventsCollection = "user_events"

const UserEventTypeConversationUpsert = "conversation_upsert"
const UserEventTypeMessageUpsert = "message_upsert"

// UserEvent represents an event related to a user, such as conversation or message updates.
type UserEvent struct {
	Id        bson.ObjectID `bson:"_id,omitempty"` // UUIDv7 - time-ordered unique identifier
	UserId    string        `bson:"user_id"`       // Identifier for the user (localpart@domain)
	EventType string        `bson:"event_type"`    // Type of the event (one of "conversation_upsert", "message_upsert")
	Payload   bson.M        `bson:"payload"`       // Event payload, structure depends on the event type
}
