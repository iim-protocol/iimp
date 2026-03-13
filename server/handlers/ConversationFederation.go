package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"github.com/iim-protocol/iimp/server/utils"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func ConversationFederation(w http.ResponseWriter, r *http.Request) {
	req, err := iimpserver.NewConversationFederationRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse ConversationFederation request: %v", err)
		iimpserver.WriteConversationFederation400Response(w, iimpserver.ConversationFederation400Response{})
		return
	}

	_, err = auth.ValidateServerToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate server token: %v", err)
		iimpserver.WriteConversationFederation401Response(w, iimpserver.ConversationFederation401Response{})
		return
	}

	conversationIdBson, err := bson.ObjectIDFromHex(req.Body.ConversationId)
	if err != nil {
		logger.Error.Printf("Failed to parse conversation ID: %v", err)
		iimpserver.WriteConversationFederation400Response(w, iimpserver.ConversationFederation400Response{})
		return
	}
	conversation, err := getConversation(req.Body)
	if err != nil {
		logger.Error.Printf("Failed to construct conversation object from request body: %v", err)
		iimpserver.WriteConversationFederation400Response(w, iimpserver.ConversationFederation400Response{})
		return
	}
	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	upsertResult, err := db.DB.Collection(dbmodels.ConversationsCollection).ReplaceOne(r.Context(), conversationFilter, conversation, options.Replace().SetUpsert(true))
	if err != nil {
		logger.Error.Printf("Failed to upsert conversation into database: %v", err)
		iimpserver.WriteConversationFederation500Response(w, iimpserver.ConversationFederation500Response{})
		return
	}
	if upsertResult.MatchedCount == 0 {
		logger.Info.Printf("Inserted new conversation with ID %s from federation request", conversation.Id.Hex())
	} else {
		logger.Info.Printf("Updated existing conversation with ID %s from federation request", conversation.Id.Hex())
	}

	// create a user event for all participants that belong to this server
	marshalledConversation, err := json.Marshal(conversation)
	if err != nil {
		logger.Error.Printf("Failed to marshal conversation for user event payload: %v", err)
		iimpserver.WriteConversationFederation500Response(w, iimpserver.ConversationFederation500Response{})
		return
	}
	for _, participant := range conversation.Participants {
		if belongs, error := utils.DoesUserIdBelongToThisServer(participant.UserId); error != nil {
			logger.Error.Printf("Failed to check if user ID %s belongs to this server: %v", participant.UserId, error)
			iimpserver.WriteConversationFederation500Response(w, iimpserver.ConversationFederation500Response{})
			return
		} else if !belongs {
			continue
		}

		event := dbmodels.UserEvent{
			UserId:    participant.UserId,
			EventType: dbmodels.UserEventTypeConversationUpsert,
			Payload:   bson.M{"conversation": string(marshalledConversation)},
		}
		_, err = db.DB.Collection(dbmodels.UserEventsCollection).InsertOne(r.Context(), event)
		if err != nil {
			logger.Error.Printf("Failed to create user event: %v", err)
			iimpserver.WriteConversationFederation500Response(w, iimpserver.ConversationFederation500Response{})
			return
		}
	}

	iimpserver.WriteConversationFederation200Response(w, iimpserver.ConversationFederation200Response{})
}

func getConversation(body iimpserver.ConversationFederationRequestBody) (dbmodels.Conversation, error) {
	convName := ""
	if body.ConversationName != nil {
		convName = *body.ConversationName
	}

	participants := make([]dbmodels.ConversationParticipant, 0)
	for _, p := range body.Participants {
		joinedAt, err := time.Parse(time.RFC3339, p.JoinedAt)
		if err != nil {
			return dbmodels.Conversation{}, fmt.Errorf("Failed to parse joinedAt for participant %v: %w", p.UserId, err)
		}
		var removedAt *bson.DateTime
		if p.RemovedAt != nil {
			rAt, err := time.Parse(time.RFC3339, *p.RemovedAt)
			if err != nil {
				return dbmodels.Conversation{}, fmt.Errorf("Failed to parse removedAt for participant %v: %w", p.UserId, err)
			}
			bRAt := bson.NewDateTimeFromTime(rAt)
			removedAt = &bRAt
		}
		participants = append(participants, dbmodels.ConversationParticipant{
			UserId:          p.UserId,
			UserDisplayName: p.UserDisplayName,
			JoinedAt:        bson.NewDateTimeFromTime(joinedAt),
			RemovedAt:       removedAt,
		})

	}

	convId, err := bson.ObjectIDFromHex(body.ConversationId)
	if err != nil {
		return dbmodels.Conversation{}, fmt.Errorf("Failed to parse conversation ID: %w", err)
	}

	return dbmodels.Conversation{
		Id:           convId,
		Name:         convName,
		OwnerId:      body.ConversationOwnerId,
		IsDM:         body.IsDM,
		Participants: participants,
	}, nil
}
