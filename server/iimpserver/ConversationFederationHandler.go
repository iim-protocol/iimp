package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	ConversationFederationRequestHTTPMethod = "POST"
	ConversationFederationRequestRoutePath  = "/api/federation/conversations"
)

// \"FEDERATION\" Create/Update a conversation from another server. This endpoint is used by other servers to create/update a conversation that includes users from the local server. UPSERT operation should be performed by the receiving server.
type ConversationFederationRequest struct {

	// Authentication parameters
	Auth ConversationFederationRequestAuthParams

	// Request body
	Body ConversationFederationRequestBody
}

type ConversationFederationRequestBody struct {

	// A unique identifier for the conversation, typically a UUIDv7.
	//
	// Required
	//
	// Must be non-empty
	ConversationId string `json:"ConversationId"`

	// An optional name for the conversation, which can be set by the client. This is not used for identification purposes and can be changed by the owner user at any time.
	//
	// Optional
	//
	ConversationName *string `json:"ConversationName,omitempty"`

	// The user ID of the owner of the conversation. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	ConversationOwnerId string `json:"ConversationOwnerId"`

	// The timestamp when the conversation was created. Format => ISO 8601 (e.g., "2024-06-01T12:00:00Z").
	//
	// Required
	//
	// Must be non-empty
	CreatedAt string `json:"CreatedAt"`

	// A list of participants in the conversation. The owner of the conversation is also included in this list. Participants can be added or removed by the owner user. Contains at least 2 participants (including the owner) for a Direct Conversation and >2 participants for a Group Conversation.
	//
	// Required
	//
	// Must be non-empty
	Participants []ConversationFederationRequestBodyParticipantsItem `json:"Participants"`
}

type ConversationFederationRequestBodyParticipantsItem struct {

	// The unique identifier of the conversation that the participant is part of. This is typically a UUIDv7.
	//
	// Required
	//
	// Must be non-empty
	ConversationId string `json:"ConversationId"`

	// The timestamp when the participant joined the conversation. Format => ISO 8601 (e.g., "2024-06-01T12:00:00Z").
	//
	// Required
	//
	// Must be non-empty
	JoinedAt string `json:"JoinedAt"`

	// The timestamp when the participant was removed from the conversation. This field is null if the participant is still part of the conversation. Format => ISO 8601 (e.g., "2024-06-01T12:00:00Z"). A removed participant will not receive new messages in the conversation but can still access the conversation history up until the time they were removed. Owner CANNOT be removed from the conversation.
	//
	// Optional
	//
	RemovedAt *string `json:"RemovedAt,omitempty"`

	// This is the display name of the participant at the time they joined the conversation. This is not updated if the user changes their display name later. This field is included to provide context about the participant's identity within the conversation, even if their global display name changes over time. During federation, the owner's server contacts the participant's server to fetch the current display name of the participant, which is then stored as UserDisplayName in the conversation participant list. This allows the conversation to maintain a consistent display name for the participant, even if they change their display name globally on their server.
	//
	// Required
	//
	// Must be non-empty
	UserDisplayName string `json:"UserDisplayName"`

	// User ID of the participant. (localpart@domain)
	//
	// Required
	//
	// Must be non-empty
	UserId string `json:"UserId"`
}

type ConversationFederationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// Server JWT signed with the requesting server's private key. This token is used for authenticating requests between servers during federation. The receiving server will verify the token using the requesting server's public key, which can be obtained from the requesting server's JWKS endpoint.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewConversationFederationRequestBody(data map[string]any) (ConversationFederationRequestBody, error) {
	var body ConversationFederationRequestBody

	valConversationId, ok := data["ConversationId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ConversationId'")

	} else {

		valConversationIdTyped, ok := valConversationId.(string)
		if !ok {
			return body, fmt.Errorf("field 'ConversationId' has incorrect type")
		}

		valConversationIdTyped = strings.TrimSpace(valConversationIdTyped)
		if len(valConversationIdTyped) == 0 {
			return body, fmt.Errorf("field 'ConversationId' must be non-empty")
		}

		body.ConversationId = valConversationIdTyped

	}

	valConversationName, ok := data["ConversationName"]
	if !ok {

		// skip, leave as zero value

	} else {

		valConversationNameTyped, ok := valConversationName.(string)
		if !ok {
			return body, fmt.Errorf("field 'ConversationName' has incorrect type")
		}

		body.ConversationName = &valConversationNameTyped

	}

	valConversationOwnerId, ok := data["ConversationOwnerId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ConversationOwnerId'")

	} else {

		valConversationOwnerIdTyped, ok := valConversationOwnerId.(string)
		if !ok {
			return body, fmt.Errorf("field 'ConversationOwnerId' has incorrect type")
		}

		valConversationOwnerIdTyped = strings.TrimSpace(valConversationOwnerIdTyped)
		if len(valConversationOwnerIdTyped) == 0 {
			return body, fmt.Errorf("field 'ConversationOwnerId' must be non-empty")
		}

		body.ConversationOwnerId = valConversationOwnerIdTyped

	}

	valCreatedAt, ok := data["CreatedAt"]
	if !ok {

		return body, fmt.Errorf("missing required field 'CreatedAt'")

	} else {

		valCreatedAtTyped, ok := valCreatedAt.(string)
		if !ok {
			return body, fmt.Errorf("field 'CreatedAt' has incorrect type")
		}

		valCreatedAtTyped = strings.TrimSpace(valCreatedAtTyped)
		if len(valCreatedAtTyped) == 0 {
			return body, fmt.Errorf("field 'CreatedAt' must be non-empty")
		}

		body.CreatedAt = valCreatedAtTyped

	}

	valParticipants, ok := data["Participants"]
	if !ok {

		return body, fmt.Errorf("missing required field 'Participants'")

	} else {

		valParticipantsSlice, ok := valParticipants.([]any)
		if !ok {
			return body, fmt.Errorf("field 'Participants' has incorrect type")
		}

		if len(valParticipantsSlice) == 0 {
			return body, fmt.Errorf("field 'Participants' must be non-empty")
		}

		valParticipantsTyped := make([]ConversationFederationRequestBodyParticipantsItem, 0, len(valParticipantsSlice))

		for idx, item := range valParticipantsSlice {
			itemMap, ok := item.(map[string]any)
			if !ok {
				return body, fmt.Errorf("element %d of field 'Participants' has incorrect type", idx)
			}
			validatedItem, err := NewConversationFederationRequestBodyParticipantsItem(itemMap)
			if err != nil {
				return body, fmt.Errorf("element %d of field 'Participants' is invalid: %w", idx, err)
			}
			valParticipantsTyped = append(valParticipantsTyped, validatedItem)
		}

		body.Participants = valParticipantsTyped

	}

	return body, nil
}

func NewConversationFederationRequestBodyParticipantsItem(data map[string]any) (ConversationFederationRequestBodyParticipantsItem, error) {
	var body ConversationFederationRequestBodyParticipantsItem

	valConversationId, ok := data["ConversationId"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ConversationId'")

	} else {

		valConversationIdTyped, ok := valConversationId.(string)
		if !ok {
			return body, fmt.Errorf("field 'ConversationId' has incorrect type")
		}

		valConversationIdTyped = strings.TrimSpace(valConversationIdTyped)
		if len(valConversationIdTyped) == 0 {
			return body, fmt.Errorf("field 'ConversationId' must be non-empty")
		}

		body.ConversationId = valConversationIdTyped

	}

	valJoinedAt, ok := data["JoinedAt"]
	if !ok {

		return body, fmt.Errorf("missing required field 'JoinedAt'")

	} else {

		valJoinedAtTyped, ok := valJoinedAt.(string)
		if !ok {
			return body, fmt.Errorf("field 'JoinedAt' has incorrect type")
		}

		valJoinedAtTyped = strings.TrimSpace(valJoinedAtTyped)
		if len(valJoinedAtTyped) == 0 {
			return body, fmt.Errorf("field 'JoinedAt' must be non-empty")
		}

		body.JoinedAt = valJoinedAtTyped

	}

	valRemovedAt, ok := data["RemovedAt"]
	if !ok {

		// skip, leave as zero value

	} else {

		valRemovedAtTyped, ok := valRemovedAt.(string)
		if !ok {
			return body, fmt.Errorf("field 'RemovedAt' has incorrect type")
		}

		body.RemovedAt = &valRemovedAtTyped

	}

	valUserDisplayName, ok := data["UserDisplayName"]
	if !ok {

		return body, fmt.Errorf("missing required field 'UserDisplayName'")

	} else {

		valUserDisplayNameTyped, ok := valUserDisplayName.(string)
		if !ok {
			return body, fmt.Errorf("field 'UserDisplayName' has incorrect type")
		}

		valUserDisplayNameTyped = strings.TrimSpace(valUserDisplayNameTyped)
		if len(valUserDisplayNameTyped) == 0 {
			return body, fmt.Errorf("field 'UserDisplayName' must be non-empty")
		}

		body.UserDisplayName = valUserDisplayNameTyped

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

// NewConversationFederationRequest creates a new ConversationFederationRequest from an http.Request and performs parameter parsing and validation.
func NewConversationFederationRequest(w http.ResponseWriter, r *http.Request) (req ConversationFederationRequest, err error) {

	valAuthorization := r.Header.Get("Authorization")
	valAuthorization = strings.TrimSpace(valAuthorization)
	if valAuthorization == "" {
		req.Auth.Authorization = nil
	} else {
		req.Auth.Authorization = &valAuthorization
	}

	// Authentication parameters validation
	// Validate required auth parameters

	if req.Auth.Authorization == nil {
		err = fmt.Errorf("missing required authentication parameter: Authorization")
		return
	}

	bodyData := make(map[string]any)

	maxBodyBytes := int64(256 << 10) // 256 KB default limit

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err = json.NewDecoder(r.Body).Decode(&bodyData)
	if err != nil {
		return
	}
	var body ConversationFederationRequestBody
	body, err = NewConversationFederationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type ConversationFederation200Response struct {
}

// Conversation stored/updated successfully from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteConversationFederation200Response(w http.ResponseWriter, response ConversationFederation200Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(200)
	return nil

}

type ConversationFederation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteConversationFederation400Response(w http.ResponseWriter, response ConversationFederation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type ConversationFederation401Response struct {
}

// Unauthorized. No valid server token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteConversationFederation401Response(w http.ResponseWriter, response ConversationFederation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type ConversationFederation403Response struct {
}

// Forbidden. Requesting server's JWT is not valid (JWT iss domain != conversation owner id domain).
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteConversationFederation403Response(w http.ResponseWriter, response ConversationFederation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type ConversationFederation404Response struct {
}

// No user IDs in the participant list exist on the receiving server.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteConversationFederation404Response(w http.ResponseWriter, response ConversationFederation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type ConversationFederation500Response struct {
}

// Internal server error while creating the conversation from federation request.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteConversationFederation500Response(w http.ResponseWriter, response ConversationFederation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
