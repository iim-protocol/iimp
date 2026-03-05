package dbmodels

import "go.mongodb.org/mongo-driver/v2/bson"

const UserPublicKeysCollection = "user_public_keys"

type UserPublicKey struct {
	Id        bson.ObjectID `bson:"_id,omitempty"` // ObjectID - time-ordered, unique, timestamp derivable
	UserId    string        `bson:"user_id"`       // localpart@domain
	PublicKey string        `bson:"public_key"`    // Base64URL encoded X25519 public key
}
