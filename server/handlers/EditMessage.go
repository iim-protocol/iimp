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

func EditMessage(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewEditMessageRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse EditMessage request: %v", err)
		iimpserver.WriteEditMessage400Response(w, iimpserver.EditMessage400Response{})
		return
	}

	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WriteEditMessage401Response(w, iimpserver.EditMessage401Response{})
		return
	}

	conversationIdBson, err := bson.ObjectIDFromHex(req.ConversationId)
	if err != nil {
		logger.Error.Printf("Failed to convert conversation ID to BSON: %v", err)
		iimpserver.WriteEditMessage400Response(w, iimpserver.EditMessage400Response{})
		return
	}

	messageIdBson, err := bson.ObjectIDFromHex(req.MessageId)
	if err != nil {
		logger.Error.Printf("Failed to convert message ID to BSON: %v", err)
		iimpserver.WriteEditMessage400Response(w, iimpserver.EditMessage400Response{})
		return
	}

	// fetch the conversation from db
	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	var conversation dbmodels.Conversation
	err = db.DB.Collection(dbmodels.ConversationsCollection).FindOne(r.Context(), conversationFilter).Decode(&conversation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteEditMessage404Response(w, iimpserver.EditMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch conversation details from database: %v", err)
		iimpserver.WriteEditMessage500Response(w, iimpserver.EditMessage500Response{})
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
		logger.Error.Printf("User '%s' is not a participant of the conversation and cannot edit messages in it", claims.Subject)
		iimpserver.WriteEditMessage403Response(w, iimpserver.EditMessage403Response{})
		return
	}

	// fetch the message from db
	messageFilter := bson.D{{Key: "_id", Value: messageIdBson}, {Key: "conversation_id", Value: conversationIdBson}}
	var message dbmodels.Message
	err = db.DB.Collection(dbmodels.MessagesCollection).FindOne(r.Context(), messageFilter).Decode(&message)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteEditMessage404Response(w, iimpserver.EditMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch message from database: %v", err)
		iimpserver.WriteEditMessage500Response(w, iimpserver.EditMessage500Response{})
		return
	}

	if message.SenderUserId != claims.Subject {
		logger.Error.Printf("User '%s' is not the sender of the message and cannot edit it", claims.Subject)
		iimpserver.WriteEditMessage403Response(w, iimpserver.EditMessage403Response{})
		return
	}

	if message.IsRedacted {
		iimpserver.WriteEditMessage403Response(w, iimpserver.EditMessage403Response{})
		return
	}

	newContentVersion := len(message.Contents) + 1
	msgTimestamp, err := time.Parse(time.RFC3339, req.Body.MessageContent.Timestamp)
	if err != nil {
		logger.Error.Printf("Failed to parse message content timestamp: %v", err)
		iimpserver.WriteEditMessage400Response(w, iimpserver.EditMessage400Response{})
		return
	}

	msgEncryptionData := make([]dbmodels.MessageEncryptionData, len(req.Body.MessageContent.EncryptionData))
	for i, ed := range req.Body.MessageContent.EncryptionData {
		msgEncryptionData[i] = dbmodels.MessageEncryptionData{
			RecipientId: ed.RecipientId,
			Encryption: dbmodels.MessageEncryption{
				KeyId:              ed.Encryption.KeyId,
				EncryptedKey:       ed.Encryption.EncryptedKey,
				EphemeralPublicKey: ed.Encryption.EphemeralPublicKey,
				EncryptedKeyNonce:  ed.Encryption.EncryptedKeyNonce,
			},
		}
	}

	message.Contents = append(message.Contents, dbmodels.MessageContentItem{
		Version: newContentVersion,
		MessageContent: dbmodels.MsgContent{
			Content:        req.Body.MessageContent.Content,
			Nonce:          req.Body.MessageContent.Nonce,
			EncryptionData: msgEncryptionData,
			Timestamp:      bson.NewDateTimeFromTime(msgTimestamp),
		},
	})

	// upsert the message
	upsertResult, err := db.DB.Collection(dbmodels.MessagesCollection).ReplaceOne(r.Context(), messageFilter, message)
	if err != nil || upsertResult.MatchedCount == 0 {
		logger.Error.Printf("Failed to update message in database: %v", err)
		iimpserver.WriteEditMessage500Response(w, iimpserver.EditMessage500Response{})
		return
	}

	// broadcast the change
	if err = broadcastMessage(r.Context(), &message, &conversation); err != nil {
		logger.Error.Printf("Failed to broadcast edited message: %v", err)
		iimpserver.WriteEditMessage500Response(w, iimpserver.EditMessage500Response{})
		return
	}

	// Success
	iimpserver.WriteEditMessage200Response(w, iimpserver.EditMessage200Response{})
}
