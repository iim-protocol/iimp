package utils

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/config"
	"go.mongodb.org/mongo-driver/v2/bson"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), config.C.PasswordBCryptCost)
	if err != nil {
		return "", fmt.Errorf("error hashing password: %w", err)
	}
	return string(hashedPassword), nil
}

func ValidatePassword(password, hashedPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, fmt.Errorf("error validating password: %w", err)
	}
	return true, nil
}

func IsValidSignUpEmail(emailId string) (bool, error) {
	domain, err := ExtractDomainFromEmailId(emailId)
	if err != nil {
		return false, err
	}

	if !slices.Contains(config.C.SignUpDomains, domain) {
		return false, nil
	}

	return true, nil
}

func ExtractDomainFromEmailId(emailId string) (string, error) {
	parts := strings.Split(emailId, "@")
	if len(parts) != 2 {
		return "", errors.New("invalid email format")
	}
	return parts[1], nil
}

func DoesUserIdBelongToThisServer(userId string) (bool, error) {
	domain, err := ExtractDomainFromUserId(userId)
	if err != nil {
		return false, err
	}

	u, err := url.Parse(config.C.Domain)
	if err != nil {
		return false, fmt.Errorf("error parsing server domain from config: %w", err)
	}
	serverDomain := u.Hostname()

	if domain != serverDomain {
		return false, nil
	}

	return true, nil
}

func ExtractDomainFromUserId(userId string) (string, error) {
	return ExtractDomainFromEmailId(userId)
}

type CreateSessionResult struct {
	Session            dbmodels.Session
	SessionToken       string
	SessionTokenExpiry time.Time
	RefreshToken       string
}

func CreateSession(userId string) (CreateSessionResult, error) {
	sessionToken, sessionTokenId, sessionTokenExpiry, err := auth.GenerateSessionToken(userId)
	if err != nil {
		return CreateSessionResult{}, fmt.Errorf("error generating session token: %w", err)
	}

	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		return CreateSessionResult{}, fmt.Errorf("error generating refresh token: %w", err)
	}

	sessionExpiry := time.Now().Add(time.Duration(config.C.SessionExpiry) * time.Second)

	session := dbmodels.Session{
		UserId: userId,
		// Set other session fields as needed
		RefreshTokenHash: auth.HashRefreshToken(refreshToken),
		ExpiresAt:        bson.NewDateTimeFromTime(sessionExpiry),
		SessionTokenId:   sessionTokenId,
	}
	return CreateSessionResult{Session: session, SessionToken: sessionToken, SessionTokenExpiry: sessionTokenExpiry, RefreshToken: refreshToken}, nil
}
