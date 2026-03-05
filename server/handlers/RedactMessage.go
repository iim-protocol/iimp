package handlers

import (
	"net/http"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func RedactMessage(w http.ResponseWriter, r *http.Request) {
	// Parse the redact message request
	req, err := iimpserver.NewRedactMessageRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse RedactMessage request: %v", err)
		iimpserver.WriteRedactMessage400Response(w, iimpserver.RedactMessage400Response{})
		return
	}

	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WriteRedactMessage401Response(w, iimpserver.RedactMessage401Response{})
		return
	}

	conversationIdBson, err := bson.ObjectIDFromHex(req.ConversationId)
	if err != nil {
		logger.Error.Printf("Failed to parse conversation ID: %v", err)
		iimpserver.WriteRedactMessage400Response(w, iimpserver.RedactMessage400Response{})
		return
	}

	messageIdBson, err := bson.ObjectIDFromHex(req.MessageId)
	if err != nil {
		logger.Error.Printf("Failed to parse message ID: %v", err)
		iimpserver.WriteRedactMessage400Response(w, iimpserver.RedactMessage400Response{})
		return
	}

	// fetch conversation from db
	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	var conversation dbmodels.Conversation
	err = db.DB.Collection(dbmodels.ConversationsCollection).FindOne(r.Context(), conversationFilter).Decode(&conversation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteRedactMessage404Response(w, iimpserver.RedactMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch conversation details from database: %v", err)
		iimpserver.WriteRedactMessage500Response(w, iimpserver.RedactMessage500Response{})
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
		iimpserver.WriteRedactMessage403Response(w, iimpserver.RedactMessage403Response{})
		return
	}

	// Check if the message exists and belongs to the conversation
	messageFilter := bson.D{{Key: "_id", Value: messageIdBson}, {Key: "conversation_id", Value: conversationIdBson}}
	var message dbmodels.Message
	err = db.DB.Collection(dbmodels.MessagesCollection).FindOne(r.Context(), messageFilter).Decode(&message)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteRedactMessage404Response(w, iimpserver.RedactMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch message details from database: %v", err)
		iimpserver.WriteRedactMessage500Response(w, iimpserver.RedactMessage500Response{})
		return
	}

	if conversation.IsDM {
		// Check if the sender of the message is the same as the user making the redact request
		if message.SenderUserId != claims.Subject {
			logger.Error.Printf("User '%s' is not the sender of message '%s'", claims.Subject, req.MessageId)
			iimpserver.WriteRedactMessage403Response(w, iimpserver.RedactMessage403Response{})
			return
		}
	} else {
		// Check if the sender of the message is the same as the user making the redact request OR the Owner of the group
		if message.SenderUserId != claims.Subject && conversation.OwnerId != claims.Subject {
			logger.Error.Printf("User '%s' is not the sender of message '%s'", claims.Subject, req.MessageId)
			iimpserver.WriteRedactMessage403Response(w, iimpserver.RedactMessage403Response{})
			return
		}
	}

	if message.IsRedacted {
		logger.Warn.Printf("Message '%s' is already redacted", req.MessageId)
		iimpserver.WriteRedactMessage200Response(w, iimpserver.RedactMessage200Response{})
		return
	}

	// Everything's valid
	message.IsRedacted = true
	_, err = db.DB.Collection(dbmodels.MessagesCollection).UpdateOne(r.Context(), messageFilter, bson.D{{Key: "$set", Value: message}})
	if err != nil {
		logger.Error.Printf("Failed to update message in database: %v", err)
		iimpserver.WriteRedactMessage500Response(w, iimpserver.RedactMessage500Response{})
		return
	}

	if err = broadcastMessage(r.Context(), &message, &conversation); err != nil {
		logger.Error.Printf("Failed to broadcast message update: %v", err)
		iimpserver.WriteRedactMessage500Response(w, iimpserver.RedactMessage500Response{})
		return
	}

	// success
	iimpserver.WriteRedactMessage200Response(w, iimpserver.RedactMessage200Response{})
}
