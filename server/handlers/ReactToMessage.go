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

func ReactToMessage(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewReactToMessageRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse ReactToMessage request: %v", err)
		iimpserver.WriteReactToMessage400Response(w, iimpserver.ReactToMessage400Response{})
		return
	}

	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WriteReactToMessage401Response(w, iimpserver.ReactToMessage401Response{})
		return
	}

	conversationIdBson, err := bson.ObjectIDFromHex(req.ConversationId)
	if err != nil {
		logger.Error.Printf("Failed to parse conversation ID: %v", err)
		iimpserver.WriteReactToMessage400Response(w, iimpserver.ReactToMessage400Response{})
		return
	}

	messageIdBson, err := bson.ObjectIDFromHex(req.MessageId)
	if err != nil {
		logger.Error.Printf("Failed to parse message ID: %v", err)
		iimpserver.WriteReactToMessage400Response(w, iimpserver.ReactToMessage400Response{})
		return
	}

	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	var conversation dbmodels.Conversation
	err = db.DB.Collection(dbmodels.ConversationsCollection).FindOne(r.Context(), conversationFilter).Decode(&conversation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteReactToMessage404Response(w, iimpserver.ReactToMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch conversation details from database: %v", err)
		iimpserver.WriteReactToMessage500Response(w, iimpserver.ReactToMessage500Response{})
		return
	}

	// Check if the user is a participant of the conversation
	isParticipant := false
	for _, participant := range conversation.Participants {
		if participant.UserId == claims.Subject && participant.RemovedAt == nil {
			isParticipant = true
			break
		}
	}
	if !isParticipant {
		logger.Error.Printf("User '%s' is not a participant of conversation '%s'", claims.Subject, req.ConversationId)
		iimpserver.WriteReactToMessage403Response(w, iimpserver.ReactToMessage403Response{})
		return
	}

	messageFilter := bson.D{{Key: "_id", Value: messageIdBson}, {Key: "conversation_id", Value: conversationIdBson}}
	var message dbmodels.Message
	err = db.DB.Collection(dbmodels.MessagesCollection).FindOne(r.Context(), messageFilter).Decode(&message)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteReactToMessage404Response(w, iimpserver.ReactToMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch message details from database: %v", err)
		iimpserver.WriteReactToMessage500Response(w, iimpserver.ReactToMessage500Response{})
		return
	}

	// Check if the message is redacted
	if message.IsRedacted {
		logger.Error.Printf("Cannot react to redacted message '%s'", req.MessageId)
		iimpserver.WriteReactToMessage403Response(w, iimpserver.ReactToMessage403Response{})
		return
	}

	for idx, usd := range message.UserSpecificData {
		if usd.RecipientId == claims.Subject {
			message.UserSpecificData[idx].Reaction = req.Body.Reaction
			dt := bson.NewDateTimeFromTime(time.Now())
			if req.Body.Reaction != nil {
				message.UserSpecificData[idx].ReactedAt = &dt
			} else {
				message.UserSpecificData[idx].ReactedAt = nil
			}
			break
		}
	}

	// upsert the message
	upsertResult, err := db.DB.Collection(dbmodels.MessagesCollection).ReplaceOne(r.Context(), messageFilter, message)
	if err != nil || upsertResult.MatchedCount == 0 {
		logger.Error.Printf("Failed to upsert message in database: %v", err)
		iimpserver.WriteReactToMessage500Response(w, iimpserver.ReactToMessage500Response{})
		return
	}

	// broadcast the message
	if err = broadcastMessage(r.Context(), &message, &conversation); err != nil {
		logger.Error.Printf("Failed to broadcast message after reaction update: %v", err)
		iimpserver.WriteReactToMessage500Response(w, iimpserver.ReactToMessage500Response{})
		return
	}

	// success
	iimpserver.WriteReactToMessage200Response(w, iimpserver.ReactToMessage200Response{})
}
