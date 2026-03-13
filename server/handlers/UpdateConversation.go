package handlers

import (
	"net/http"
	"slices"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func UpdateConversation(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewUpdateConversationRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse UpdateConversation request: %v", err)
		iimpserver.WriteUpdateConversation400Response(w, iimpserver.UpdateConversation400Response{})
		return
	}

	// validate the session
	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WriteUpdateConversation401Response(w, iimpserver.UpdateConversation401Response{})
		return
	}

	// fetch the conversation from the database
	var conversation dbmodels.Conversation
	conversationIdBson, err := bson.ObjectIDFromHex(req.ConversationId)
	if err != nil {
		iimpserver.WriteUpdateConversation400Response(w, iimpserver.UpdateConversation400Response{})
		return
	}
	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	err = db.DB.Collection(dbmodels.ConversationsCollection).FindOne(r.Context(), conversationFilter).Decode(&conversation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteUpdateConversation404Response(w, iimpserver.UpdateConversation404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch conversation from database: %v", err)
		iimpserver.WriteUpdateConversation500Response(w, iimpserver.UpdateConversation500Response{})
		return
	}

	if conversation.OwnerId != claims.Subject || conversation.IsDM {
		logger.Error.Printf("User %s is not the owner of conversation %s OR conversation is a DM", claims.Subject, req.ConversationId)
		iimpserver.WriteUpdateConversation403Response(w, iimpserver.UpdateConversation403Response{})
		return
	}

	convUpdated := false

	// update the conversation name if provided
	if req.Body.ConversationName != nil {
		convUpdated = true
		conversation.Name = *req.Body.ConversationName
	}

	if len(req.Body.ParticipantUserIdsToAdd) > 0 {
		convUpdated = true
		for _, id := range req.Body.ParticipantUserIdsToAdd {
			participant, err := createConversationParticipantObject(r.Context(), id)
			if err != nil {
				switch err.Reason {
				case CreateConversationParticipantObjectErrorReasonInvalidUserId:
					iimpserver.WriteUpdateConversation400Response(w, iimpserver.UpdateConversation400Response{})
					return
				case CreateConversationParticipantObjectErrorReasonLocalUserDoesNotExist:
					iimpserver.WriteUpdateConversation404Response(w, iimpserver.UpdateConversation404Response{})
					return
				case CreateConversationParticipantObjectErrorReasonFailedToFetchLocalUserInfo, CreateConversationParticipantObjectErrorReasonErrorGeneratingServerToken, CreateConversationParticipantObjectErrorReasonFailedDiscoveryOfRemoteServer, CreateConversationParticipantObjectErrorReasonFailedToFetchRemoteUserInfo:
					iimpserver.WriteUpdateConversation500Response(w, iimpserver.UpdateConversation500Response{})
					return
				default:
					iimpserver.WriteUpdateConversation500Response(w, iimpserver.UpdateConversation500Response{})
					return
				}
			}
			conversation.Participants = append(conversation.Participants, participant)
		}
	}

	if len(req.Body.ParticipantUserIdsToRemove) > 0 {
		convUpdated = true
		removalTimestamp := bson.NewDateTimeFromTime(time.Now())
		for idx, participant := range conversation.Participants {
			if participant.UserId != conversation.OwnerId && slices.Contains(req.Body.ParticipantUserIdsToRemove, participant.UserId) {
				conversation.Participants[idx].RemovedAt = &removalTimestamp
			}
		}
	}

	if !convUpdated {
		logger.Error.Printf("No valid fields provided for update in conversation %s by user %s", req.ConversationId, claims.Subject)
		iimpserver.WriteUpdateConversation400Response(w, iimpserver.UpdateConversation400Response{})
		return
	}

	// upsert the conversation in the database
	upsertResult, err := db.DB.Collection(dbmodels.ConversationsCollection).ReplaceOne(r.Context(), conversationFilter, conversation, options.Replace().SetUpsert(true))
	if err != nil || upsertResult.MatchedCount == 0 {
		logger.Error.Printf("Upsert matched 0 conversations or Failed to upsert conversation in database: %v", err)
		iimpserver.WriteUpdateConversation500Response(w, iimpserver.UpdateConversation500Response{})
		return
	}

	err = broadcastConversation(r.Context(), &conversation, req.Body.ParticipantUserIdsToRemove)
	if err != nil {
		logger.Error.Printf("Failed to broadcast conversation update: %v", err)
		iimpserver.WriteUpdateConversation500Response(w, iimpserver.UpdateConversation500Response{})
		return
	}

	var responseConvName *string
	if conversation.Name != "" {
		responseConvName = &conversation.Name
	}

	responseParticipants := make([]iimpserver.UpdateConversation200ResponseBodyConversationParticipantsItem, len(conversation.Participants))
	for i, participant := range conversation.Participants {
		var removedAt *string
		if participant.RemovedAt != nil {
			t := participant.RemovedAt.Time().Format(time.RFC3339)
			removedAt = &t
		}

		responseParticipants[i] = iimpserver.UpdateConversation200ResponseBodyConversationParticipantsItem{
			UserId:          participant.UserId,
			UserDisplayName: participant.UserDisplayName,
			JoinedAt:        participant.JoinedAt.Time().Format(time.RFC3339),
			RemovedAt:       removedAt,
		}
	}

	iimpserver.WriteUpdateConversation200Response(w, iimpserver.UpdateConversation200Response{
		Body: iimpserver.UpdateConversation200ResponseBody{
			Conversation: iimpserver.UpdateConversation200ResponseBodyConversation{
				ConversationId:      conversation.Id.Hex(),
				ConversationName:    responseConvName,
				ConversationOwnerId: claims.Subject,
				IsDM:                conversation.IsDM,
				CreatedAt:           conversation.Id.Timestamp().Format(time.RFC3339),
				Participants:        responseParticipants,
			},
		},
	})
}
