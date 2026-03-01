package db

import "go.mongodb.org/mongo-driver/v2/bson"

const SessionsCollection = "sessions"

type Session struct {
	ID               bson.ObjectID `bson:"_id,omitempty"`      // UUIDv7 - time-ordered unique identifier
	UserId           string        `bson:"user_id"`            // Identifier for the user (localpart@domain)
	RefreshTokenHash string        `bson:"refresh_token_hash"` // Secure random token for session refresh
	ExpiresAt        bson.DateTime `bson:"expires_at"`         // Expiration timestamp, Refresh Token won't work after this time
	SessionTokenId   string        `bson:"session_token_id"`   // Unique identifier for the session token (e.g., UUIDv7)
}
