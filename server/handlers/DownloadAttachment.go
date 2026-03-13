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

func DownloadAttachment(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewDownloadAttachmentRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse DownloadAttachment request: %v", err)
		iimpserver.WriteDownloadAttachment400Response(w, iimpserver.DownloadAttachment400Response{})
		return
	}

	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WriteDownloadAttachment401Response(w, iimpserver.DownloadAttachment401Response{})
		return
	}

	conversationIdBson, err := bson.ObjectIDFromHex(req.ConversationId)
	if err != nil {
		logger.Error.Printf("Failed to parse conversation ID: %v", err)
		iimpserver.WriteDownloadAttachment400Response(w, iimpserver.DownloadAttachment400Response{})
		return
	}

	messageIdBson, err := bson.ObjectIDFromHex(req.MessageId)
	if err != nil {
		logger.Error.Printf("Failed to parse message ID: %v", err)
		iimpserver.WriteDownloadAttachment400Response(w, iimpserver.DownloadAttachment400Response{})
		return
	}

	fileIdBson, err := bson.ObjectIDFromHex(req.FileId)
	if err != nil {
		logger.Error.Printf("Failed to parse file ID: %v", err)
		iimpserver.WriteDownloadAttachment400Response(w, iimpserver.DownloadAttachment400Response{})
		return
	}

	// fetch conversation from db
	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	var conversation dbmodels.Conversation
	err = db.DB.Collection(dbmodels.ConversationsCollection).FindOne(r.Context(), conversationFilter).Decode(&conversation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			logger.Error.Printf("Conversation not found: %s", conversationIdBson.Hex())
			iimpserver.WriteDownloadAttachment404Response(w, iimpserver.DownloadAttachment404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch conversation details from database: %v", err)
		iimpserver.WriteDownloadAttachment500Response(w, iimpserver.DownloadAttachment500Response{})
		return
	}

	// Check if the user is a participant of the conversation
	isParticipant := false
	for _, participant := range conversation.Participants {
		if participant.UserId == claims.Subject && (participant.RemovedAt == nil || (participant.RemovedAt != nil && participant.RemovedAt.Time().After(messageIdBson.Timestamp()))) {
			isParticipant = true
			break
		}
	}
	if !isParticipant {
		logger.Error.Printf("User %s is not a participant of conversation %s", claims.Subject, conversationIdBson.Hex())
		iimpserver.WriteDownloadAttachment403Response(w, iimpserver.DownloadAttachment403Response{})
		return
	}

	// Check if the message exists
	messageFilter := bson.D{{Key: "_id", Value: messageIdBson}, {Key: "conversation_id", Value: conversationIdBson}}
	var message dbmodels.Message
	err = db.DB.Collection(dbmodels.MessagesCollection).FindOne(r.Context(), messageFilter).Decode(&message)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			logger.Error.Printf("Message not found: %s", messageIdBson.Hex())
			iimpserver.WriteDownloadAttachment404Response(w, iimpserver.DownloadAttachment404Response{})
			return
		}
		logger.Error.Printf("Failed to fetch message details from database: %v", err)
		iimpserver.WriteDownloadAttachment500Response(w, iimpserver.DownloadAttachment500Response{})
		return
	}

	hasAttachment := false
	for _, a := range message.Attachments {
		if a.FileId.Hex() == fileIdBson.Hex() {
			hasAttachment = true
			break
		}
	}
	if !hasAttachment {
		logger.Error.Printf("Attachment not found: %s", fileIdBson.Hex())
		iimpserver.WriteDownloadAttachment404Response(w, iimpserver.DownloadAttachment404Response{})
		return
	}

	_, err = db.Bucket.DownloadToStream(r.Context(), fileIdBson, w)
	if err != nil {
		logger.Error.Printf("Failed to download attachment: %v", err)
		return
	}
}
