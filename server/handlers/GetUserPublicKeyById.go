package handlers

import (
	"net/http"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func GetUserPublicKeyById(w http.ResponseWriter, r *http.Request) {
	req, err := iimpserver.NewGetUserPublicKeyByIdRequest(w, r)
	if err != nil {
		logger.Error.Println("error parsing GetUserPublicKeyById request:", err)
		iimpserver.WriteGetUserPublicKeyById400Response(w, iimpserver.GetUserPublicKeyById400Response{})
		return
	}

	var userPublicKey dbmodels.UserPublicKey
	filter := bson.D{{Key: "_id", Value: req.KeyId}, {Key: "user_id", Value: req.UserId}}

	err = db.DB.Collection(dbmodels.UserPublicKeysCollection).FindOne(r.Context(), filter).Decode(&userPublicKey)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteGetUserPublicKeyById404Response(w, iimpserver.GetUserPublicKeyById404Response{})
			return
		}
		logger.Error.Println("error fetching user public key from database:", err)
		iimpserver.WriteGetUserPublicKeyById500Response(w, iimpserver.GetUserPublicKeyById500Response{})
		return
	}

	// Return the user's public key in the response
	iimpserver.WriteGetUserPublicKeyById200Response(w, iimpserver.GetUserPublicKeyById200Response{
		Body: iimpserver.GetUserPublicKeyById200ResponseBody{
			KeyId:      userPublicKey.Id,
			PublicKey:  userPublicKey.PublicKey,
			UploadedAt: userPublicKey.Timestamp.Time().Format(time.RFC3339),
			UserId:     userPublicKey.UserId,
		},
	})
}
