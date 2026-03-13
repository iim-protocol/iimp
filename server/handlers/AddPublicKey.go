package handlers

import (
	"net/http"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func AddPublicKey(w http.ResponseWriter, r *http.Request) {
	// Parse the request
	req, err := iimpserver.NewAddPublicKeyRequest(w, r)
	if err != nil {
		logger.Error.Println("error parsing AddPublicKey request:", err)
		iimpserver.WriteAddPublicKey400Response(w, iimpserver.AddPublicKey400Response{})
		return
	}

	// Validate Session
	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Println("error validating session token for AddPublicKey request:", err)
		iimpserver.WriteAddPublicKey401Response(w, iimpserver.AddPublicKey401Response{})
		return
	}

	timestamp, err := time.Parse(time.RFC3339, req.Body.Timestamp)

	publicKey := dbmodels.UserPublicKey{
		Id:        req.Body.KeyId,
		UserId:    claims.Subject,
		PublicKey: req.Body.PublicKey,
		Timestamp: bson.NewDateTimeFromTime(timestamp),
	}

	_, err = db.DB.Collection(dbmodels.UserPublicKeysCollection).InsertOne(r.Context(), publicKey)
	if err != nil {
		logger.Error.Println("error inserting public key into database for AddPublicKey request:", err)
		iimpserver.WriteAddPublicKey500Response(w, iimpserver.AddPublicKey500Response{})
		return
	}

	iimpserver.WriteAddPublicKey201Response(w, iimpserver.AddPublicKey201Response{})
}
