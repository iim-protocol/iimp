package db

import "go.mongodb.org/mongo-driver/v2/bson"

const UsersCollection = "users"

type User struct {
	ID           bson.ObjectID `bson:"_id,omitempty"` // MongoDB document ID
	UserId       string        `bson:"user_id"`       // identifier for the user (e.g., localpart@domain )
	Email        string        `bson:"email"`         // email address for the user
	DisplayName  string        `bson:"display_name"`  // display name for the user
	PasswordHash string        `bson:"password_hash"` // bcrypt hash of the user's password
}
