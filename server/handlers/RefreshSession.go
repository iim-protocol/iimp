package handlers

import (
	"net/http"
	"time"

	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func RefreshSession(w http.ResponseWriter, r *http.Request) {
	// Parse the refresh session request
	req, err := iimpserver.NewRefreshSessionRequest(w, r)
	if err != nil {
		logger.Error.Println("error parsing RefreshSession request:", err)
		iimpserver.WriteRefreshSession400Response(w, iimpserver.RefreshSession400Response{})
		return
	}

	refreshTokenHash := auth.HashRefreshToken(req.Body.RefreshToken)

	filters := bson.D{{Key: "refresh_token_hash", Value: refreshTokenHash}}
	var session db.Session

	// Get session from database using refresh token hash
	err = db.DB.Collection(db.SessionsCollection).FindOne(r.Context(), filters).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteRefreshSession401Response(w, iimpserver.RefreshSession401Response{})
			return
		}
		logger.Error.Println("error fetching session from database for RefreshSession request:", err)
		iimpserver.WriteRefreshSession500Response(w, iimpserver.RefreshSession500Response{})
		return
	}

	if session.ExpiresAt.Time().Before(time.Now()) {
		iimpserver.WriteRefreshSession401Response(w, iimpserver.RefreshSession401Response{})
		return
	}

	// Generate new session token
	newSessionToken, sessionTokenId, expiry, err := auth.GenerateSessionToken(session.UserId)
	if err != nil {
		logger.Error.Println("error generating new session token for RefreshSession request:", err)
		iimpserver.WriteRefreshSession500Response(w, iimpserver.RefreshSession500Response{})
		return
	}

	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		logger.Error.Println("error generating new refresh token for RefreshSession request:", err)
		iimpserver.WriteRefreshSession500Response(w, iimpserver.RefreshSession500Response{})
		return
	}

	session.SessionTokenId = sessionTokenId
	if _, err := db.DB.Collection(db.SessionsCollection).UpdateOne(r.Context(), filters, bson.D{{Key: "$set", Value: bson.D{
		{Key: "session_token_id", Value: sessionTokenId},
		{Key: "refresh_token_hash", Value: auth.HashRefreshToken(refreshToken)},
	}}}); err != nil {
		logger.Error.Println("error updating session token in database for RefreshSession request:", err)
		iimpserver.WriteRefreshSession500Response(w, iimpserver.RefreshSession500Response{})
		return
	}

	iimpserver.WriteRefreshSession200Response(w, iimpserver.RefreshSession200Response{
		Body: iimpserver.RefreshSession200ResponseBody{
			SessionToken:       newSessionToken,
			SessionTokenExpiry: expiry.Format(time.RFC3339),
			RefreshToken:       refreshToken,
			RefreshTokenExpiry: session.ExpiresAt.Time().Format(time.RFC3339),
		},
	})
}
