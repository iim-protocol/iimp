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

func MessageFederation(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewMessageFederationRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse MessageFederation request: %v", err)
		iimpserver.WriteMessageFederation400Response(w, iimpserver.MessageFederation400Response{})
		return
	}

	_, err = auth.ValidateServerToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate server token: %v", err)
		iimpserver.WriteMessageFederation401Response(w, iimpserver.MessageFederation401Response{})
		return
	}

	conversationIdBson, err := bson.ObjectIDFromHex(req.ConversationId)
	if err != nil {
		logger.Error.Printf("Failed to parse conversation ID: %v", err)
		iimpserver.WriteMessageFederation400Response(w, iimpserver.MessageFederation400Response{})
		return
	}

	conversationFilter := bson.D{{Key: "_id", Value: conversationIdBson}}
	var conversation dbmodels.Conversation
	err = db.DB.Collection(dbmodels.ConversationsCollection).FindOne(r.Context(), conversationFilter).Decode(&conversation)
	if err != nil {
		logger.Error.Printf("Failed to find conversation: %v", err)
		iimpserver.WriteMessageFederation404Response(w, iimpserver.MessageFederation404Response{})
		return
	}

	localParticipantIds := make([]string, 0)
	for _, p := range conversation.Participants {
		if belongs, err := utils.DoesUserIdBelongToThisServer(p.UserId); err != nil {
			logger.Error.Printf("Error checking if user ID belongs to this server: %v", err)
			iimpserver.WriteMessageFederation500Response(w, iimpserver.MessageFederation500Response{})
			return
		} else if !belongs {
			continue
		}
		localParticipantIds = append(localParticipantIds, p.UserId)
	}

	// If there are no local participants, return 404
	if len(localParticipantIds) == 0 {
		logger.Error.Printf("No local participants found for conversation: %v", conversation.Id.Hex())
		iimpserver.WriteMessageFederation404Response(w, iimpserver.MessageFederation404Response{})
		return
	}

	messageIdBson, err := bson.ObjectIDFromHex(req.Body.MessageId)
	if err != nil {
		logger.Error.Printf("Failed to parse message ID: %v", err)
		iimpserver.WriteMessageFederation400Response(w, iimpserver.MessageFederation400Response{})
		return
	}
	message, err := getMessage(req.Body)
	if err != nil {
		logger.Error.Printf("Failed to construct message from request body: %v", err)
		iimpserver.WriteMessageFederation400Response(w, iimpserver.MessageFederation400Response{})
		return
	}
	messageFilter := bson.D{{Key: "_id", Value: messageIdBson}, {Key: "conversation_id", Value: conversationIdBson}}
	upsertResult, err := db.DB.Collection(dbmodels.MessagesCollection).ReplaceOne(
		r.Context(),
		messageFilter,
		message,
		options.Replace().SetUpsert(true),
	)
	if err != nil {
		logger.Error.Printf("Failed to upsert message into database: %v", err)
		iimpserver.WriteMessageFederation500Response(w, iimpserver.MessageFederation500Response{})
		return
	}
	if upsertResult.MatchedCount > 0 {
		logger.Info.Printf("Updated existing message with ID %s in conversation %s", message.Id.Hex(), conversation.Id.Hex())
	} else if upsertResult.UpsertedCount > 0 {
		logger.Info.Printf("Inserted new message with ID %s in conversation %s", message.Id.Hex(), conversation.Id.Hex())
	} else {
		logger.Error.Printf("Failed to upsert message: no documents matched or upserted")
		iimpserver.WriteMessageFederation500Response(w, iimpserver.MessageFederation500Response{})
		return
	}

	// do user events
	marshalledMessage, err := json.Marshal(message)
	if err != nil {
		logger.Error.Printf("Failed to marshal message for user event payload: %v", err)
		iimpserver.WriteMessageFederation500Response(w, iimpserver.MessageFederation500Response{})
		return
	}
	for _, participantId := range localParticipantIds {
		event := dbmodels.UserEvent{
			UserId:    participantId,
			EventType: dbmodels.UserEventTypeMessageUpsert,
			Payload:   bson.M{"message": string(marshalledMessage)},
		}
		_, err = db.DB.Collection(dbmodels.UserEventsCollection).InsertOne(r.Context(), event)
		if err != nil {
			logger.Error.Printf("Failed to create user event: %v", err)
			iimpserver.WriteMessageFederation500Response(w, iimpserver.MessageFederation500Response{})
			return
		}
	}

	iimpserver.WriteMessageFederation200Response(w, iimpserver.MessageFederation200Response{})
}

func getMessage(body iimpserver.MessageFederationRequestBody) (dbmodels.Message, error) {
	messageIdBson, err := bson.ObjectIDFromHex(body.MessageId)
	if err != nil {
		return dbmodels.Message{}, fmt.Errorf("failed to parse message ID: %v", err)
	}

	conversationIdBson, err := bson.ObjectIDFromHex(body.ConversationId)
	if err != nil {
		return dbmodels.Message{}, fmt.Errorf("failed to parse conversation ID: %v", err)
	}

	attachments := make([]dbmodels.Attachment, 0)
	for _, attachment := range body.Attachments {
		fileId, err := bson.ObjectIDFromHex(attachment.FileId)
		if err != nil {
			return dbmodels.Message{}, fmt.Errorf("failed to parse attachment file ID: %v", err)
		}
		attachments = append(attachments, dbmodels.Attachment{
			FileId:          fileId,
			Filename:        attachment.Filename,
			ContentType:     attachment.ContentType,
			Size:            int64(attachment.Size),
			FileHash:        attachment.FileHash,
			AttachmentNonce: attachment.AttachmentNonce,
		})
	}

	usd := make([]dbmodels.MessageUserSpecificDataItem, 0)

	for _, item := range body.UserSpecificData {
		var readAt, reactedAt *bson.DateTime
		if item.ReadAt != nil {
			t, err := time.Parse(time.RFC3339, *item.ReadAt)
			if err != nil {
				return dbmodels.Message{}, fmt.Errorf("failed to parse readAt timestamp: %v", err)
			}
			bt := bson.NewDateTimeFromTime(t)
			readAt = &bt
		}

		if item.ReactedAt != nil {
			t, err := time.Parse(time.RFC3339, *item.ReactedAt)
			if err != nil {
				return dbmodels.Message{}, fmt.Errorf("failed to parse reactedAt timestamp: %v", err)
			}
			bt := bson.NewDateTimeFromTime(t)
			reactedAt = &bt
		}

		usd = append(usd, dbmodels.MessageUserSpecificDataItem{
			RecipientId: item.RecipientId,
			Reaction:    item.Reaction,
			ReadAt:      readAt,
			ReactedAt:   reactedAt,
		})
	}

	contents := make([]dbmodels.MessageContentItem, 0)

	for _, content := range body.Contents {
		encryptionData := make([]dbmodels.MessageEncryptionData, 0, len(content.MessageContent.EncryptionData))
		for _, ed := range content.MessageContent.EncryptionData {
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
		msgTimestamp, err := time.Parse(time.RFC3339, content.MessageContent.Timestamp)
		if err != nil {
			return dbmodels.Message{}, fmt.Errorf("failed to parse message content timestamp: %v", err)
		}
		bt := bson.NewDateTimeFromTime(msgTimestamp)
		contents = append(contents, dbmodels.MessageContentItem{
			Version: int(content.Version),
			MessageContent: dbmodels.MsgContent{
				Content:        content.MessageContent.Content,
				Nonce:          content.MessageContent.Nonce,
				EncryptionData: encryptionData,
				Timestamp:      bt,
			},
		})
	}

	return dbmodels.Message{
		Id:               messageIdBson,
		ConversationId:   conversationIdBson,
		SenderUserId:     body.SenderUserId,
		IsRedacted:       body.IsRedacted,
		UserSpecificData: usd,
		Contents:         contents,
		Attachments:      attachments,
	}, nil
}
