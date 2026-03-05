package handlers

import (
	"net/http"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func NewConversation(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewNewConversationRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse NewConversation request: %v", err)
		iimpserver.WriteNewConversation400Response(w, iimpserver.NewConversation400Response{})
		return
	}

	// validate the session
	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WriteNewConversation401Response(w, iimpserver.NewConversation401Response{})
		return
	}

	var ownerUser dbmodels.User
	ownerUserFilter := bson.D{{Key: "user_id", Value: claims.Subject}}
	err = db.DB.Collection(dbmodels.UsersCollection).FindOne(r.Context(), ownerUserFilter).Decode(&ownerUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteNewConversation401Response(w, iimpserver.NewConversation401Response{})
			return
		}
		logger.Error.Printf("Failed to fetch owner user details from database: %v", err)
		iimpserver.WriteNewConversation500Response(w, iimpserver.NewConversation500Response{})
		return
	}

	// Init convo object
	conversationName := ""
	if req.Body.ConversationName != nil {
		conversationName = *req.Body.ConversationName
	}
	conversation := dbmodels.Conversation{
		Name:    conversationName,
		OwnerId: claims.Subject,
		IsDM:    len(req.Body.ParticipantUserIds) == 1, // 2 participant = DM (1 participant + owner), more than 2 participants = group chat
		Participants: []dbmodels.ConversationParticipant{
			{
				UserId:          claims.Subject,
				UserDisplayName: ownerUser.DisplayName,
				JoinedAt:        bson.NewDateTimeFromTime(time.Now()),
				RemovedAt:       nil,
			},
		},
	}

	participantIds := req.Body.ParticipantUserIds
	for _, id := range participantIds {
		participant, err := createConversationParticipantObject(r.Context(), id)
		if err != nil {
			switch err.Reason {
			case CreateConversationParticipantObjectErrorReasonInvalidUserId:
				iimpserver.WriteNewConversation400Response(w, iimpserver.NewConversation400Response{})
				return
			case CreateConversationParticipantObjectErrorReasonLocalUserDoesNotExist:
				iimpserver.WriteNewConversation404Response(w, iimpserver.NewConversation404Response{})
				return
			case CreateConversationParticipantObjectErrorReasonFailedToFetchLocalUserInfo, CreateConversationParticipantObjectErrorReasonErrorGeneratingServerToken, CreateConversationParticipantObjectErrorReasonFailedDiscoveryOfRemoteServer, CreateConversationParticipantObjectErrorReasonFailedToFetchRemoteUserInfo:
				iimpserver.WriteNewConversation500Response(w, iimpserver.NewConversation500Response{})
				return
			default:
				iimpserver.WriteNewConversation500Response(w, iimpserver.NewConversation500Response{})
				return
			}
		}

		conversation.Participants = append(conversation.Participants, participant)
	}
	insertResult, err := db.DB.Collection(dbmodels.ConversationsCollection).InsertOne(r.Context(), conversation)
	if err != nil {
		logger.Error.Printf("Failed to insert conversation into database: %v", err)
		iimpserver.WriteNewConversation500Response(w, iimpserver.NewConversation500Response{})
		return
	}

	conversationIdBson, ok := insertResult.InsertedID.(bson.ObjectID)
	if !ok {
		logger.Error.Printf("Failed to convert inserted conversation ID to ObjectID: %v", insertResult.InsertedID)
		iimpserver.WriteNewConversation500Response(w, iimpserver.NewConversation500Response{})
		return
	}
	// Update the conversation object with the generated ID for response and federation purposes
	conversation.Id = conversationIdBson

	conversationId := conversationIdBson.Hex()

	var responseConvName *string
	if conversationName != "" {
		responseConvName = &conversationName
	}

	responseParticipants := make([]iimpserver.NewConversation201ResponseBodyConversationParticipantsItem, len(conversation.Participants))
	for i, participant := range conversation.Participants {
		var removedAt *string
		if participant.RemovedAt != nil {
			t := participant.RemovedAt.Time().Format(time.RFC3339)
			removedAt = &t
		}

		responseParticipants[i] = iimpserver.NewConversation201ResponseBodyConversationParticipantsItem{
			UserId:          participant.UserId,
			UserDisplayName: participant.UserDisplayName,
			JoinedAt:        participant.JoinedAt.Time().Format(time.RFC3339),
			RemovedAt:       removedAt,
		}
	}

	// Before writing the response, perform federation
	err = broadcastConversation(r.Context(), &conversation, []string{})
	if err != nil {
		logger.Error.Printf("Failed to notify federated servers about new conversation: %v", err)
		iimpserver.WriteNewConversation500Response(w, iimpserver.NewConversation500Response{})
		return
	}

	iimpserver.WriteNewConversation201Response(w, iimpserver.NewConversation201Response{
		Body: iimpserver.NewConversation201ResponseBody{
			Conversation: iimpserver.NewConversation201ResponseBodyConversation{
				ConversationId:      conversationId,
				ConversationName:    responseConvName,
				ConversationOwnerId: claims.Subject,
				IsDM:                conversation.IsDM,
				CreatedAt:           conversationIdBson.Timestamp().Format(time.RFC3339),
				Participants:        responseParticipants,
			},
		},
	})
}
