package handlers

import (
	"fmt"
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

const MB = 1024 * 1024

func NewMessage(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewNewMessageRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse NewMessage request: %v", err)
		iimpserver.WriteNewMessage400Response(w, iimpserver.NewMessage400Response{})
		return
	}

	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WriteNewMessage401Response(w, iimpserver.NewMessage401Response{})
		return
	}

	conversationIdBson, err := bson.ObjectIDFromHex(req.ConversationId)
	if err != nil {
		logger.Error.Printf("Failed to parse conversation ID: %v", err)
		iimpserver.WriteNewMessage400Response(w, iimpserver.NewMessage400Response{})
		return
	}

	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	var conversation dbmodels.Conversation
	err = db.DB.Collection(dbmodels.ConversationsCollection).FindOne(r.Context(), conversationFilter).Decode(&conversation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			iimpserver.WriteNewMessage404Response(w, iimpserver.NewMessage404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch conversation details from database: %v", err)
		iimpserver.WriteNewMessage500Response(w, iimpserver.NewMessage500Response{})
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
		logger.Error.Printf("User %s is not a participant of conversation %s", claims.Subject, req.ConversationId)
		iimpserver.WriteNewMessage403Response(w, iimpserver.NewMessage403Response{})
		return
	}

	message, err := makeMessageFromNewMessageRequest(&req, conversationIdBson, claims.Subject)
	if err != nil {
		iimpserver.WriteNewMessage400Response(w, iimpserver.NewMessage400Response{})
		return
	}

	_, err = db.DB.Collection(dbmodels.MessagesCollection).InsertOne(r.Context(), message)
	if err != nil {
		logger.Error.Printf("Failed to save message to database: %v", err)
		iimpserver.WriteNewMessage500Response(w, iimpserver.NewMessage500Response{})
		return
	}

	err = broadcastMessage(r.Context(), &message, &conversation)
	if err != nil {
		logger.Error.Printf("Failed to broadcast message: %v", err)
		iimpserver.WriteNewMessage500Response(w, iimpserver.NewMessage500Response{})
		return
	}

	// Message successfully saved and broadcasted

	iimpserver.WriteNewMessage201Response(w, iimpserver.NewMessage201Response{})
}

func makeMessageFromNewMessageRequest(req *iimpserver.NewMessageRequest, conversationIdBson bson.ObjectID, senderUserId string) (dbmodels.Message, error) {
	attachments := make([]dbmodels.Attachment, 0, len(req.Body.Attachments))
	for _, attachment := range req.Body.Attachments {
		fileId, err := bson.ObjectIDFromHex(attachment.FileId)
		if err != nil {
			logger.Error.Printf("Failed to parse attachment file ID: %v", err)
			return dbmodels.Message{}, fmt.Errorf("failed to parse attachment file ID: %v", err)
		}
		if attachment.Size > 1000*MB {
			logger.Error.Printf("Attachment size exceeds limit: %v bytes", attachment.Size)
			return dbmodels.Message{}, fmt.Errorf("attachment size exceeds limit: %v bytes", attachment.Size)
		}
		attachments = append(attachments, dbmodels.Attachment{
			FileId:      fileId,
			Filename:    attachment.Filename,
			ContentType: attachment.ContentType,
			Size:        int64(attachment.Size),
		})
	}
	msgTimestamp, err := time.Parse(time.RFC3339, req.Body.MessageContent.Timestamp)
	if err != nil {
		logger.Error.Printf("Failed to parse message content timestamp: %v", err)
		return dbmodels.Message{}, fmt.Errorf("failed to parse message content timestamp: %v", err)
	}

	encryptionData := make([]dbmodels.MessageEncryptionData, 0, len(req.Body.MessageContent.EncryptionData))
	for _, ed := range req.Body.MessageContent.EncryptionData {
		encryptionData = append(encryptionData, dbmodels.MessageEncryptionData{
			RecipientId: ed.RecipientId,
			Encryption: dbmodels.MessageEncryption{
				KeyId:              ed.Encryption.KeyId,
				EncryptedKey:       ed.Encryption.EncryptedKey,
				EphemeralPublicKey: ed.Encryption.EphemeralPublicKey,
				EncryptedKeyNonce:  ed.Encryption.EncryptedKeyNonce,
			},
		})
	}

	contents := make([]dbmodels.MessageContentItem, 0, 1)
	contents = append(contents, dbmodels.MessageContentItem{
		Version: 1,
		MessageContent: dbmodels.MsgContent{
			Content:        req.Body.MessageContent.Content,
			Nonce:          req.Body.MessageContent.Nonce,
			Timestamp:      bson.NewDateTimeFromTime(msgTimestamp),
			EncryptionData: encryptionData,
		},
	})

	userSpecificData := make([]dbmodels.MessageUserSpecificDataItem, 0, len(req.Body.MessageContent.EncryptionData))
	for _, ed := range req.Body.MessageContent.EncryptionData {
		userSpecificData = append(userSpecificData, dbmodels.MessageUserSpecificDataItem{
			RecipientId: ed.RecipientId,
			ReadAt:      nil,
			Reaction:    nil,
			ReactedAt:   nil,
		})
	}

	return dbmodels.Message{
		ConversationId:   conversationIdBson,
		SenderUserId:     senderUserId,
		IsRedacted:       false,
		Attachments:      attachments,
		Contents:         contents,
		UserSpecificData: userSpecificData,
	}, nil
}
