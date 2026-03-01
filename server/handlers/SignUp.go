package handlers

import (
	"net/http"

	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"github.com/iim-protocol/iimp/server/utils"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	req, err := iimpserver.NewSignUpRequest(w, r)
	if err != nil {
		logger.Error.Println("error parsing SignUp request:", err)
		iimpserver.WriteSignUp400Response(w, iimpserver.SignUp400Response{})
		return
	}

	isValidEmail, err := utils.IsValidSignUpEmail(req.Body.Email)
	if err != nil {
		logger.Error.Println("error validating email domain for SignUp request:", err)
		iimpserver.WriteSignUp400Response(w, iimpserver.SignUp400Response{})
		return
	}

	if !isValidEmail {
		iimpserver.WriteSignUp403Response(w, iimpserver.SignUp403Response{})
		return
	}

	hashedPassword, err := utils.HashPassword(req.Body.Password)
	if err != nil {
		logger.Error.Println("error hashing password for SignUp request:", err)
		iimpserver.WriteSignUp500Response(w, iimpserver.SignUp500Response{})
		return
	}

	_, err = db.DB.Collection(db.UsersCollection).InsertOne(r.Context(), db.User{
		UserId:       req.Body.UserId,
		Email:        req.Body.Email,
		DisplayName:  req.Body.DisplayName,
		PasswordHash: hashedPassword,
	})
	if err != nil {
		// check if mongo.WriteError
		writeError, ok := err.(mongo.WriteException)
		if ok && len(writeError.WriteErrors) > 0 {
			writeError := writeError.WriteErrors[0]
			if writeError.Code == 11000 {
				iimpserver.WriteSignUp409Response(w, iimpserver.SignUp409Response{})
				return
			}
		}

		commandError, ok := err.(mongo.CommandError)
		if ok && commandError.Code == 11000 {
			iimpserver.WriteSignUp409Response(w, iimpserver.SignUp409Response{})
			return
		}
		logger.Error.Println("error inserting new user into database for SignUp request:", err)
		iimpserver.WriteSignUp500Response(w, iimpserver.SignUp500Response{})
		return
	}

	iimpserver.WriteSignUp201Response(w, iimpserver.SignUp201Response{})
}
