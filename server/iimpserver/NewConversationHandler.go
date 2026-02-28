package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	NewConversationRequestHTTPMethod = "POST"
	NewConversationRequestRoutePath  = "/api/client/conversations"
)

// Create a new conversation.
type NewConversationRequest struct {

	// Authentication parameters
	Auth NewConversationRequestAuthParams

	// Request body
	Body NewConversationRequestBody
}

type NewConversationRequestBody struct {

	// A name for the conversation, which can be set by the client. This is not used for identification purposes and can be changed by the owner user at any time.
	//
	// Optional
	//
	ConversationName *string `json:"ConversationName,omitempty"`

	// A list of user IDs for the participants to be added to the conversation. For a Direct Conversation, this list must contain exactly 2 user IDs (owner + participant). For a Group Conversation, this list must contain at least 3 user IDs (owner + 2 others).
	//
	// Required
	//
	// Must be non-empty
	ParticipantUserIds []string `json:"ParticipantUserIds"`
}

type NewConversationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewNewConversationRequestBody(data map[string]any) (NewConversationRequestBody, error) {
	var body NewConversationRequestBody

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

	valParticipantUserIds, ok := data["ParticipantUserIds"]
	if !ok {

		return body, fmt.Errorf("missing required field 'ParticipantUserIds'")

	} else {

		valParticipantUserIdsSlice, ok := valParticipantUserIds.([]any)
		if !ok {
			return body, fmt.Errorf("field 'ParticipantUserIds' has incorrect type")
		}

		if len(valParticipantUserIdsSlice) == 0 {
			return body, fmt.Errorf("field 'ParticipantUserIds' must be non-empty")
		}

		valParticipantUserIdsTyped := make([]string, 0, len(valParticipantUserIdsSlice))

		for idx, item := range valParticipantUserIdsSlice {
			itemTyped, ok := item.(string)
			if !ok {
				return body, fmt.Errorf("element %d of field 'ParticipantUserIds' has incorrect type", idx)
			}

			itemTyped = strings.TrimSpace(itemTyped)
			if itemTyped == "" {
				return body, fmt.Errorf("element %d of field 'ParticipantUserIds' must be non-empty", idx)
			}

			valParticipantUserIdsTyped = append(valParticipantUserIdsTyped, itemTyped)
		}

		body.ParticipantUserIds = valParticipantUserIdsTyped

	}

	return body, nil
}

// NewNewConversationRequest creates a new NewConversationRequest from an http.Request and performs parameter parsing and validation.
func NewNewConversationRequest(w http.ResponseWriter, r *http.Request) (req NewConversationRequest, err error) {

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
	var body NewConversationRequestBody
	body, err = NewNewConversationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type NewConversation201Response struct {

	// Response body
	Body NewConversation201ResponseBody
}

type NewConversation201ResponseBodyConversationParticipantsItem struct {

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

type NewConversation201ResponseBodyConversation struct {

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
	Participants []NewConversation201ResponseBodyConversationParticipantsItem `json:"Participants"`
}

type NewConversation201ResponseBody struct {

	// Details of the created conversation.
	//
	// Optional
	//
	Conversation *NewConversation201ResponseBodyConversation `json:"Conversation,omitempty"`
}

// Conversation created successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewConversation201Response(w http.ResponseWriter, response NewConversation201Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(201)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type NewConversation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewConversation400Response(w http.ResponseWriter, response NewConversation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type NewConversation401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewConversation401Response(w http.ResponseWriter, response NewConversation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type NewConversation403Response struct {
}

// Forbidden. One or more user IDs in the participant list are not allowed to be added to the conversation.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewConversation403Response(w http.ResponseWriter, response NewConversation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type NewConversation404Response struct {
}

// One or more user IDs in the participant list do not exist.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewConversation404Response(w http.ResponseWriter, response NewConversation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type NewConversation500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteNewConversation500Response(w http.ResponseWriter, response NewConversation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
