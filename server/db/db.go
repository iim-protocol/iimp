package db

import (
	"context"

	"github.com/iim-protocol/iimp/server/config"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var Client *mongo.Client
var DB *mongo.Database
var Bucket *mongo.GridFSBucket

// Connect establishes a connection to the MongoDB database using the provided URI and assigns the client to the package-level variable.
func Connect(ctx context.Context, mongoURI string) (err error) {
	Client, err = mongo.Connect(options.Client().ApplyURI(mongoURI))
	if err != nil {
		return err
	}
	DB = Client.Database(config.C.MongoDBName)
	Bucket = DB.GridFSBucket()

	users := DB.Collection(UsersCollection)
	if _, err = users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "user_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}
	if _, err = users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}

	sessions := DB.Collection(SessionsCollection)
	if _, err = sessions.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "user_id", Value: 1}},
	}); err != nil {
		return err
	}
	if _, err = sessions.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}); err != nil {
		return err
	}

	userPublicKeys := DB.Collection(UserPublicKeysCollection)
	if _, err = userPublicKeys.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "user_id", Value: 1}},
	}); err != nil {
		return err
	}

	return nil
}

func Disconnect(ctx context.Context) error {
	return Client.Disconnect(ctx)
}
