package handlers

import (
	"net/http"
	"time"

	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func GetUserPublicKey(w http.ResponseWriter, r *http.Request) {
	req, err := iimpserver.NewGetUserPublicKeyRequest(w, r)
	if err != nil {
		logger.Error.Println("error parsing GetUserPublicKey request:", err)
		iimpserver.WriteGetUserPublicKey400Response(w, iimpserver.GetUserPublicKey400Response{})
		return
	}

	var userPublicKey db.UserPublicKey

	// Fetch the user's public key from the database
	filter := bson.D{{Key: "user_id", Value: req.UserId}}
	opts := options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})

	err = db.DB.Collection(db.UserPublicKeysCollection).FindOne(r.Context(), filter, opts).Decode(&userPublicKey)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteGetUserPublicKey404Response(w, iimpserver.GetUserPublicKey404Response{})
			return
		}
		logger.Error.Println("error fetching user public key from database:", err)
		iimpserver.WriteGetUserPublicKey500Response(w, iimpserver.GetUserPublicKey500Response{})
		return
	}

	// Return the user's public key in the response
	iimpserver.WriteGetUserPublicKey200Response(w, iimpserver.GetUserPublicKey200Response{
		Body: iimpserver.GetUserPublicKey200ResponseBody{
			KeyId:      userPublicKey.Id.Hex(),
			PublicKey:  userPublicKey.PublicKey,
			UploadedAt: userPublicKey.Id.Timestamp().Format(time.RFC3339),
			UserId:     userPublicKey.UserId,
		},
	})
}
