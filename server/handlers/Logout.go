package handlers

import (
	"net/http"
	"strings"

	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	// Parse the logout request
	req, err := iimpserver.NewLogoutRequest(w, r)
	if err != nil {
		logger.Error.Println("error parsing Logout request:", err)
		iimpserver.WriteLogout400Response(w, iimpserver.Logout400Response{})
		return
	}

	sessionToken := strings.TrimPrefix(*req.Auth.Authorization, "Bearer ")

	// Validate session token
	claims, err := auth.ValidateSessionToken(sessionToken)
	if err != nil {
		logger.Error.Println("error validating session token for Logout request:", err)
		iimpserver.WriteLogout401Response(w, iimpserver.Logout401Response{})
		return
	}

	// Invalidate the session token (implementation depends on how sessions are stored)
	filter := bson.D{{Key: "session_token_id", Value: claims.ID}}
	_, err = db.DB.Collection(db.SessionsCollection).DeleteOne(r.Context(), filter)
	if err != nil {
		logger.Error.Println("error invalidating session token for Logout request:", err)
		iimpserver.WriteLogout500Response(w, iimpserver.Logout500Response{})
		return
	}

	iimpserver.WriteLogout204Response(w, iimpserver.Logout204Response{})
}
