package iimpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	UpdateConversationRequestHTTPMethod = "PUT"
	UpdateConversationRequestRoutePath  = "/api/client/conversations/{conversationId}"
)

// Update an existing conversation. Only for Group Conversations, Direct Conversations cannot be updated.
type UpdateConversationRequest struct {

	// Source: path parameter "{conversationId}"
	//

	// The unique identifier of the conversation to update. This is typically a UUIDv7.
	//
	// Required
	ConversationId string

	// Authentication parameters
	Auth UpdateConversationRequestAuthParams

	// Request body
	Body UpdateConversationRequestBody
}

type UpdateConversationRequestBody struct {

	// An updated name for the conversation, which can be set by the client. This is not used for identification purposes and can be changed by the owner user at any time.
	//
	// Optional
	//
	ConversationName *string `json:"ConversationName,omitempty"`

	// A list of user IDs for the participants to be added to the conversation.
	//
	// Optional
	//
	ParticipantUserIdsToAdd []string `json:"ParticipantUserIdsToAdd,omitempty"`

	// A list of user IDs for the participants to be removed from the conversation. The owner user cannot be removed from the conversation and should not be included in this list.
	//
	// Optional
	//
	ParticipantUserIdsToRemove []string `json:"ParticipantUserIdsToRemove,omitempty"`
}

type UpdateConversationRequestAuthParams struct {

	// Required Authentication Method
	// Source: header "Authorization"
	//
	// A token used to authenticate the client session. This token is obtained after a successful login and must be included in the header of subsequent requests to access protected resources.
	//
	// Format (NOT ENFORCED): Bearer <JWT (RFC 7519)>
	//
	Authorization *string
}

func NewUpdateConversationRequestBody(data map[string]any) (UpdateConversationRequestBody, error) {
	var body UpdateConversationRequestBody

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

	valParticipantUserIdsToAdd, ok := data["ParticipantUserIdsToAdd"]
	if !ok {

		// skip, leave as zero value

	} else {

		valParticipantUserIdsToAddSlice, ok := valParticipantUserIdsToAdd.([]any)
		if !ok {
			return body, fmt.Errorf("field 'ParticipantUserIdsToAdd' has incorrect type")
		}

		valParticipantUserIdsToAddTyped := make([]string, 0, len(valParticipantUserIdsToAddSlice))

		for idx, item := range valParticipantUserIdsToAddSlice {
			itemTyped, ok := item.(string)
			if !ok {
				return body, fmt.Errorf("element %d of field 'ParticipantUserIdsToAdd' has incorrect type", idx)
			}

			itemTyped = strings.TrimSpace(itemTyped)
			if itemTyped == "" {
				return body, fmt.Errorf("element %d of field 'ParticipantUserIdsToAdd' must be non-empty", idx)
			}

			valParticipantUserIdsToAddTyped = append(valParticipantUserIdsToAddTyped, itemTyped)
		}

		body.ParticipantUserIdsToAdd = valParticipantUserIdsToAddTyped

	}

	valParticipantUserIdsToRemove, ok := data["ParticipantUserIdsToRemove"]
	if !ok {

		// skip, leave as zero value

	} else {

		valParticipantUserIdsToRemoveSlice, ok := valParticipantUserIdsToRemove.([]any)
		if !ok {
			return body, fmt.Errorf("field 'ParticipantUserIdsToRemove' has incorrect type")
		}

		valParticipantUserIdsToRemoveTyped := make([]string, 0, len(valParticipantUserIdsToRemoveSlice))

		for idx, item := range valParticipantUserIdsToRemoveSlice {
			itemTyped, ok := item.(string)
			if !ok {
				return body, fmt.Errorf("element %d of field 'ParticipantUserIdsToRemove' has incorrect type", idx)
			}

			itemTyped = strings.TrimSpace(itemTyped)
			if itemTyped == "" {
				return body, fmt.Errorf("element %d of field 'ParticipantUserIdsToRemove' must be non-empty", idx)
			}

			valParticipantUserIdsToRemoveTyped = append(valParticipantUserIdsToRemoveTyped, itemTyped)
		}

		body.ParticipantUserIdsToRemove = valParticipantUserIdsToRemoveTyped

	}

	return body, nil
}

// NewUpdateConversationRequest creates a new UpdateConversationRequest from an http.Request and performs parameter parsing and validation.
func NewUpdateConversationRequest(w http.ResponseWriter, r *http.Request) (req UpdateConversationRequest, err error) {

	valConversationId, err := parsestringParam(r.PathValue("conversationId"), "path: conversationId", true)
	if err != nil {
		return
	}

	req.ConversationId = *valConversationId

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
	var body UpdateConversationRequestBody
	body, err = NewUpdateConversationRequestBody(bodyData)
	if err != nil {
		return
	}
	req.Body = body
	defer r.Body.Close()

	return
}

type UpdateConversation200Response struct {

	// Response body
	Body UpdateConversation200ResponseBody
}

type UpdateConversation200ResponseBodyConversationParticipantsItem struct {

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

type UpdateConversation200ResponseBodyConversation struct {

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
	Participants []UpdateConversation200ResponseBodyConversationParticipantsItem `json:"Participants"`
}

type UpdateConversation200ResponseBody struct {

	// Details of the updated conversation.
	//
	// Optional
	//
	Conversation *UpdateConversation200ResponseBodyConversation `json:"Conversation,omitempty"`
}

// Conversation updated successfully.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUpdateConversation200Response(w http.ResponseWriter, response UpdateConversation200Response) error {
	// Set headers, if any

	// Set Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Set status code and write the header
	w.WriteHeader(200)

	// Write body
	return json.NewEncoder(w).Encode(response.Body)

}

type UpdateConversation400Response struct {
}

// Invalid input data.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUpdateConversation400Response(w http.ResponseWriter, response UpdateConversation400Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(400)
	return nil

}

type UpdateConversation401Response struct {
}

// Unauthorized. No valid session token provided.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUpdateConversation401Response(w http.ResponseWriter, response UpdateConversation401Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(401)
	return nil

}

type UpdateConversation403Response struct {
}

// Forbidden. The authenticated user is not allowed to update the conversation since they are not the owner of the conversation or the conversation is a Direct Conversation.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUpdateConversation403Response(w http.ResponseWriter, response UpdateConversation403Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(403)
	return nil

}

type UpdateConversation404Response struct {
}

// Conversation not found.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUpdateConversation404Response(w http.ResponseWriter, response UpdateConversation404Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(404)
	return nil

}

type UpdateConversation500Response struct {
}

// Internal server error.
//
// This function WILL CALL w.WriteHeader(), so ensure that no other calls to
// w.WriteHeader() are made before calling this function.
func WriteUpdateConversation500Response(w http.ResponseWriter, response UpdateConversation500Response) error {
	// Set headers, if any

	// Set status code and write the header
	w.WriteHeader(500)
	return nil

}
