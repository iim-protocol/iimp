package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	ResetPasswordRequestHTTPMethod = "POST"
	ResetPasswordRequestRoutePath  = "/api/client/reset-password"
)

// Reset the password for the user account.
type ResetPasswordRequest struct {

	// Request body
	Body ResetPasswordRequestBody
}

type ResetPasswordRequestBody struct {

	// New password for the account.
	//
	// Required
	//
	// Must be non-empty
	NewPassword string `json:"NewPassword"`

	// A token sent to the user's email address as part of the password reset process. This token is used to verify the password reset request.
	//
	// Required
	//
	// Must be non-empty
	ResetToken string `json:"ResetToken"`

	// User ID for the account.
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

func NewResetPasswordRequestBody(data map[string]any) (ResetPasswordRequestBody, error) {
	var body ResetPasswordRequestBody

	valNewPassword, ok := data["NewPassword"]
	if !ok {

		return body, fmt.Errorf("missing required field 'NewPassword'")

	} else {

		valNewPasswordTyped, ok := valNewPassword.(string)
		if !ok {
			return body, fmt.Errorf("field 'NewPassword' has incorrect type")
		}

		valNewPasswordTyped = strings.TrimSpace(valNewPasswordTyped)
		if len(valNewPasswordTyped) == 0 {
			return body, fmt.Errorf("field 'NewPassword' must be non-empty")
		}

		body.NewPassword = valNewPasswordTyped

	}

	valResetToken, ok := data["ResetToken"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ResetToken'")

	} else {

		valResetTokenTyped, ok := valResetToken.(string)
		if !ok {
			return body, fmt.Errorf("field 'ResetToken' has incorrect type")
		}

		valResetTokenTyped = strings.TrimSpace(valResetTokenTyped)
		if len(valResetTokenTyped) == 0 {
			return body, fmt.Errorf("field 'ResetToken' must be non-empty")
		}

		body.ResetToken = valResetTokenTyped

	}

	valUserId, ok := data["UserId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'UserId'")

	} else {

		valUserIdTyped, ok := valUserId.(string)
		if !ok {
			return body, fmt.Errorf("field 'UserId' has incorrect type")
		}

		valUserIdTyped = strings.TrimSpace(valUserIdTyped)
		if len(valUserIdTyped) == 0 {
			return body, fmt.Errorf("field 'UserId' must be non-empty")
		}

		body.UserId = valUserIdTyped

	}

	return body, nil
}

// NewResetPasswordRequest creates a new ResetPasswordRequest from an http.Request and performs parameter parsing and validation.
func NewResetPasswordRequest(w http.ResponseWriter, r *http.Request) (req ResetPasswordRequest, err error) {

	bodyData := make(map[string]any)

	maxBodyBytes := int64(256 << 10) // 256 KB default limit

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err = json.NewDecoder(r.Body).Decode(&bodyData)
	if err != nil {
		return
	}
	var body ResetPasswordRequestBody
	body, err = NewResetPasswordRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type ResetPassword200Response struct {
}

// Password reset successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteResetPassword200Response(w http.ResponseWriter, response ResetPassword200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type ResetPassword401Response struct {
}

// Invalid or expired reset token or input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteResetPassword401Response(w http.ResponseWriter, response ResetPassword401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type ResetPassword500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteResetPassword500Response(w http.ResponseWriter, response ResetPassword500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
