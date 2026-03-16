package handlers

import (
	"net/http"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func GetUserInfoFederation(w http.ResponseWriter, r *http.Request) {
	req, err := iimpserver.NewGetUserInfoFederationRequest(w, r)
	if err != nil {
		logger.Error.Printf("Error parsing GetUserInfoFederationRequest: %v", err)
		iimpserver.WriteGetUserInfoFederation400Response(w, iimpserver.GetUserInfoFederation400Response{})
		return
	}

	_, err = auth.ValidateServerToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Error validating server token: %v", err)
		iimpserver.WriteGetUserInfoFederation401Response(w, iimpserver.GetUserInfoFederation401Response{})
		return
	}

	var user dbmodels.User
	userFilter := bson.D{{Key: "user_id", Value: req.UserId}}
	err = db.DB.Collection(dbmodels.UsersCollection).FindOne(r.Context(), userFilter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteGetUserInfoFederation404Response(w, iimpserver.GetUserInfoFederation404Response{})
			return
		}
		logger.Error.Printf("Error fetching user information from database: %v", err)
		iimpserver.WriteGetUserInfoFederation404Response(w, iimpserver.GetUserInfoFederation404Response{})
		return
	}

	resp := iimpserver.GetUserInfoFederation200Response{
		Body: iimpserver.GetUserInfoFederation200ResponseBody{
			DisplayName: user.DisplayName,
			UserId:      user.UserId,
		},
	}
	iimpserver.WriteGetUserInfoFederation200Response(w, resp)
}
