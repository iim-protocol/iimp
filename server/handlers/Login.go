package handlers

import (
	"net/http"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"github.com/iim-protocol/iimp/server/utils"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func Login(w http.ResponseWriter, r *http.Request) {
	// Parse the login request
	req, err := iimpserver.NewLoginRequest(w, r)
	if err != nil {
		logger.Error.Println("error parsing Login request:", err)
		iimpserver.WriteLogin400Response(w, iimpserver.Login400Response{})
		return
	}

	// Fetch the user with given userId
	filter := bson.D{{Key: "user_id", Value: req.Body.UserId}}

	var result dbmodels.User

	err = db.DB.Collection(dbmodels.UsersCollection).FindOne(r.Context(), filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteLogin401Response(w, iimpserver.Login401Response{})
			return
		}
		logger.Error.Println("error fetching user from database for Login request:", err)
		iimpserver.WriteLogin500Response(w, iimpserver.Login500Response{})
		return
	}

	// Check if the password is correct
	if valid, err := utils.ValidatePassword(req.Body.Password, result.PasswordHash); err != nil {
		logger.Error.Println("error validating password for Login request:", err)
		iimpserver.WriteLogin500Response(w, iimpserver.Login500Response{})
		return
	} else if !valid {
		iimpserver.WriteLogin401Response(w, iimpserver.Login401Response{})
		return
	}

	// Create a new session for the user
	session, err := utils.CreateSession(result.UserId)
	if err != nil {
		logger.Error.Println("error creating session for Login request:", err)
		iimpserver.WriteLogin500Response(w, iimpserver.Login500Response{})
		return
	}

	_, err = db.DB.Collection(dbmodels.SessionsCollection).InsertOne(r.Context(), session.Session)
	if err != nil {
		logger.Error.Println("error inserting session into database for Login request:", err)
		iimpserver.WriteLogin500Response(w, iimpserver.Login500Response{})
		return
	}

	// Return the session information
	iimpserver.WriteLogin200Response(w, iimpserver.Login200Response{
		Body: iimpserver.Login200ResponseBody{
			SessionToken:       session.SessionToken,
			SessionTokenExpiry: session.SessionTokenExpiry.Format(time.RFC3339),
			RefreshToken:       session.RefreshToken,
			RefreshTokenExpiry: session.Session.ExpiresAt.Time().Format(time.RFC3339),
		},
	})
}
