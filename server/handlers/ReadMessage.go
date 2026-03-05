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

func ReadMessage(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewReadMessageRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse ReadMessage request: %v", err)
		iimpserver.WriteReadMessage400Response(w, iimpserver.ReadMessage400Response{})
		return
	}

	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WriteReadMessage401Response(w, iimpserver.ReadMessage401Response{})
		return
	}

	conversationIdBson, err := bson.ObjectIDFromHex(req.ConversationId)
	if err != nil {
		logger.Error.Printf("Failed to parse conversation ID: %v", err)
		iimpserver.WriteReadMessage400Response(w, iimpserver.ReadMessage400Response{})
		return
	}

	messageIdBson, err := bson.ObjectIDFromHex(req.MessageId)
	if err != nil {
		logger.Error.Printf("Failed to parse message ID: %v", err)
		iimpserver.WriteReadMessage400Response(w, iimpserver.ReadMessage400Response{})
		return
	}

	// fetch the conversation from the database
	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	var conversation dbmodels.Conversation
	err = db.DB.Collection(dbmodels.ConversationsCollection).FindOne(r.Context(), conversationFilter).Decode(&conversation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteReadMessage404Response(w, iimpserver.ReadMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch conversation details from database: %v", err)
		iimpserver.WriteReadMessage500Response(w, iimpserver.ReadMessage500Response{})
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
		iimpserver.WriteReadMessage403Response(w, iimpserver.ReadMessage403Response{})
		return
	}

	var message dbmodels.Message
	messageFilter := bson.D{{Key: "_id", Value: messageIdBson}, {Key: "conversation_id", Value: conversationIdBson}}
	err = db.DB.Collection(dbmodels.MessagesCollection).FindOne(r.Context(), messageFilter).Decode(&message)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteReadMessage404Response(w, iimpserver.ReadMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch message details from database: %v", err)
		iimpserver.WriteReadMessage500Response(w, iimpserver.ReadMessage500Response{})
		return
	}

	userFoundInUSD := false

	for i, usd := range message.UserSpecificData {
		if usd.RecipientId == claims.Subject {
			if usd.ReadAt != nil {
				// Message is already marked as read for this user, no need to update
				iimpserver.WriteReadMessage200Response(w, iimpserver.ReadMessage200Response{})
				return
			}
			dt := bson.NewDateTimeFromTime(time.Now())
			message.UserSpecificData[i].ReadAt = &dt
			userFoundInUSD = true
			break
		}
	}

	if !userFoundInUSD {
		logger.Error.Printf("User-specific data for user '%s' not found in message '%s'", claims.Subject, req.MessageId)
		iimpserver.WriteReadMessage404Response(w, iimpserver.ReadMessage404Response{})
		return
	}

	// upsert the message
	upsertResult, err := db.DB.Collection(dbmodels.MessagesCollection).ReplaceOne(r.Context(), messageFilter, message)
	if err != nil || upsertResult.MatchedCount == 0 {
		logger.Error.Printf("Failed to update message read receipt in database: %v", err)
		iimpserver.WriteReadMessage500Response(w, iimpserver.ReadMessage500Response{})
		return
	}

	// broadcast the message
	if err = broadcastMessage(r.Context(), &message, &conversation); err != nil {
		logger.Error.Printf("Failed to broadcast message read receipt: %v", err)
		iimpserver.WriteReadMessage500Response(w, iimpserver.ReadMessage500Response{})
		return
	}

	// success
	iimpserver.WriteReadMessage200Response(w, iimpserver.ReadMessage200Response{})
}
