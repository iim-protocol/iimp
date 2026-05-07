package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/logger"
	"github.com/iim-protocol/iimp/server/utils"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// broadcastConversation function notifies federated servers about a new conversation.
//
// It also creates user events for local participants.
//
// If a participant was removed, they will not receive the conversation federation request, but if they were removed in this update (i.e. their RemovedAt was just set), they will still receive the conversation federation request, but with the RemovedAt field set, so that their local server can know that they were removed.
//
// If an error occurs, the error is returned and further federation is not processed.
func broadcastConversation(ctx context.Context, conversation *dbmodels.Conversation, removedParticipantsUserIds []string) error {
	participants := []iimp_go_client.ConversationFederationRequestBodyParticipantsItem{}
	for _, participant := range conversation.Participants {
		var removedAt *string
		if participant.RemovedAt != nil {
			t := participant.RemovedAt.Time().Format(time.RFC3339)
			removedAt = &t
		}

		participants = append(participants, iimp_go_client.ConversationFederationRequestBodyParticipantsItem{
			UserId:          participant.UserId,
			UserDisplayName: participant.UserDisplayName,
			JoinedAt:        participant.JoinedAt.Time().Format(time.RFC3339),
			RemovedAt:       removedAt,
		})
	}

	var conversationName *string
	if conversation.Name != "" {
		conversationName = &conversation.Name
	}

	requestBody := iimp_go_client.ConversationFederationRequestBody{
		ConversationId:      conversation.Id.Hex(),
		ConversationName:    conversationName,
		IsDM:                conversation.IsDM,
		ConversationOwnerId: conversation.OwnerId,
		CreatedAt:           conversation.Id.Timestamp().Format(time.RFC3339),
		Participants:        participants,
	}

	for _, participant := range conversation.Participants {
		if participant.RemovedAt != nil {
			if !slices.Contains(removedParticipantsUserIds, participant.UserId) {
				continue
			}
		}
		// we create events for all local users, including the owner
		if isLocalUser, _ := utils.DoesUserIdBelongToThisServer(participant.UserId); !isLocalUser {
			// We ignore the error here as the previous call to DoesUserIdBelongToThisServer returns an error
			// if the domain extraction failed, so if we're here, domain extraction must not have failed.
			domain, _ := utils.ExtractDomainFromUserId(participant.UserId)
			baseUrl := "https://" + domain
			iimpClient := iimp_go_client.NewIIMP(baseUrl)

			jwt, err := auth.GenerateServerToken(baseUrl)
			if err != nil {
				return fmt.Errorf("failed to generate server token for '%s': %w", domain, err)
			}
			serverToken := "Bearer " + jwt

			res, err := iimpClient.ConversationFederation(ctx, iimp_go_client.ConversationFederationRequest{
				Auth: iimp_go_client.ConversationFederationRequestAuthParams{
					Authorization: &serverToken,
				},
				Body: requestBody,
			})
			if err != nil {
				return err
			} else if res.StatusCode != 200 {
				return fmt.Errorf("received non-200 response from federated server '%s': %d", domain, res.StatusCode)
			}
		} else {
			// Create user event for local participant
			marshalledConversation, err := json.Marshal(conversation)
			if err != nil {
				return fmt.Errorf("failed to marshal conversation for user event: %w", err)
			}
			userEvent := dbmodels.UserEvent{
				UserId:    participant.UserId,
				EventType: dbmodels.UserEventTypeConversationUpsert,
				Payload:   bson.M{"conversation": string(marshalledConversation)},
			}

			if _, err := db.DB.Collection(dbmodels.UserEventsCollection).InsertOne(ctx, userEvent); err != nil {
				return fmt.Errorf("failed to create user event for participant '%s': %w", participant.UserId, err)
			}
		}
	}
	return nil
}

type CreateConversationParticipantObjectErrorReason string

var (
	// Should prolly return 400
	CreateConversationParticipantObjectErrorReasonInvalidUserId CreateConversationParticipantObjectErrorReason = "invalid_user_id"

	// Should prolly return 500
	CreateConversationParticipantObjectErrorReasonFailedDiscoveryOfRemoteServer CreateConversationParticipantObjectErrorReason = "failed_discovery_of_remote_server"

	// Should Prolly return 500
	CreateConversationParticipantObjectErrorReasonErrorGeneratingServerToken CreateConversationParticipantObjectErrorReason = "error_generating_server_token"

	// Should prolly return 500
	CreateConversationParticipantObjectErrorReasonFailedToFetchRemoteUserInfo CreateConversationParticipantObjectErrorReason = "failed_to_fetch_remote_user_info"

	// Should prolly return 404
	CreateConversationParticipantObjectErrorReasonLocalUserDoesNotExist CreateConversationParticipantObjectErrorReason = "local_user_does_not_exist"

	// Should prolly return 500
	CreateConversationParticipantObjectErrorReasonFailedToFetchLocalUserInfo CreateConversationParticipantObjectErrorReason = "failed_to_fetch_local_user_info"
)

type CreateConversationParticipantObjectError struct {
	Reason CreateConversationParticipantObjectErrorReason
	err    error
}

func (c *CreateConversationParticipantObjectError) Error() string {
	return fmt.Errorf("reason: %s, error: %w", c.Reason, c.err).Error()
}

func createConversationParticipantObject(ctx context.Context, userId string) (dbmodels.ConversationParticipant, *CreateConversationParticipantObjectError) {
	isLocalUser, err := utils.DoesUserIdBelongToThisServer(userId)
	if err != nil {
		return dbmodels.ConversationParticipant{}, &CreateConversationParticipantObjectError{
			Reason: CreateConversationParticipantObjectErrorReasonInvalidUserId,
			err:    err,
		}
	}

	if isLocalUser {
		var user dbmodels.User
		filter := bson.D{{Key: "user_id", Value: userId}}
		err = db.DB.Collection(dbmodels.UsersCollection).FindOne(ctx, filter).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				logger.Error.Printf("Participant user ID '%s' does not exist", userId)
				return dbmodels.ConversationParticipant{}, &CreateConversationParticipantObjectError{
					Reason: CreateConversationParticipantObjectErrorReasonLocalUserDoesNotExist,
					err:    err,
				}
			}
			logger.Error.Printf("Failed to fetch user details from database for participant user ID '%s': %v", userId, err)
			return dbmodels.ConversationParticipant{}, &CreateConversationParticipantObjectError{
				Reason: CreateConversationParticipantObjectErrorReasonFailedToFetchLocalUserInfo,
				err:    err,
			}
		}

		return dbmodels.ConversationParticipant{
			UserId:          userId,
			UserDisplayName: user.DisplayName,
			JoinedAt:        bson.NewDateTimeFromTime(time.Now()),
			RemovedAt:       nil,
		}, nil
	} else {
		// We ignore the error here as the previous call to DoesUserIdBelongToThisServer returns an error
		// if the domain extraction failed, so if we're here, domain extraction must not have failed.
		domain, _ := utils.ExtractDomainFromUserId(userId)

		baseUrl := "https://" + domain

		// Get user details using federation api
		iimpClient := iimp_go_client.NewIIMP(baseUrl)

		// Check if IIMP server exists
		discoverRes, err := iimpClient.DiscoverServer(ctx, iimp_go_client.DiscoverServerRequest{})
		if err != nil || discoverRes.StatusCode != 200 {
			logger.Error.Printf("Failed to discover server for participant user ID '%s': %v", userId, err)
			return dbmodels.ConversationParticipant{}, &CreateConversationParticipantObjectError{
				Reason: CreateConversationParticipantObjectErrorReasonFailedDiscoveryOfRemoteServer,
				err:    err,
			}
		}
		// TODO: We do not check for version mismatch, since we do not implement backwards compatibility yet.

		// Create server jwt
		jwt, err := auth.GenerateServerToken(discoverRes.Response200.Body.Domain)
		if err != nil {
			logger.Error.Printf("Failed to generate server token for participant user ID '%s': %v", userId, err)
			return dbmodels.ConversationParticipant{}, &CreateConversationParticipantObjectError{
				Reason: CreateConversationParticipantObjectErrorReasonErrorGeneratingServerToken,
				err:    err,
			}
		}

		authorization := "Bearer " + jwt
		userInfoRes, err := iimpClient.GetUserInfoFederation(ctx, iimp_go_client.GetUserInfoFederationRequest{
			UserId: userId,
			Auth: iimp_go_client.GetUserInfoFederationRequestAuthParams{
				Authorization: &authorization,
			},
		})
		if err != nil || userInfoRes.StatusCode != 200 {
			logger.Error.Printf("Failed to fetch user info for participant user ID '%s': %v", userId, err)
			return dbmodels.ConversationParticipant{}, &CreateConversationParticipantObjectError{
				Reason: CreateConversationParticipantObjectErrorReasonFailedToFetchRemoteUserInfo,
				err:    err,
			}
		}

		return dbmodels.ConversationParticipant{
			UserId:          userId,
			UserDisplayName: userInfoRes.Response200.Body.DisplayName,
			JoinedAt:        bson.NewDateTimeFromTime(time.Now()),
			RemovedAt:       nil,
		}, nil
	}
}

func broadcastMessage(ctx context.Context, message *dbmodels.Message, conversation *dbmodels.Conversation) error {
	messageFederationRequestBody := createMessageBroadcastRequestBody(message, conversation)
	for _, participant := range conversation.Participants {
		if participant.RemovedAt != nil {
			continue
		}

		isLocalUser, err := utils.DoesUserIdBelongToThisServer(participant.UserId)
		if err != nil {
			return fmt.Errorf("failed to determine if message sender is local: %w", err)
		} else if isLocalUser {
			// Local user, create a new user event
			marshalledMessage, err := json.Marshal(message)
			if err != nil {
				return fmt.Errorf("failed to marshal message for user event: %w", err)
			}
			userEvent := dbmodels.UserEvent{
				UserId:    participant.UserId,
				EventType: dbmodels.UserEventTypeMessageUpsert,
				Payload:   bson.M{"message": string(marshalledMessage)},
			}

			if _, err := db.DB.Collection(dbmodels.UserEventsCollection).InsertOne(ctx, userEvent); err != nil {
				return fmt.Errorf("failed to create user event for participant '%s': %w", participant.UserId, err)
			}
		} else {
			// User is on another server, federate the message
			domain, _ := utils.ExtractDomainFromUserId(participant.UserId)
			baseUrl := "https://" + domain
			iimpClient := iimp_go_client.NewIIMP(baseUrl)

			jwt, err := auth.GenerateServerToken(baseUrl)
			if err != nil {
				return fmt.Errorf("failed to generate server token for '%s': %w", domain, err)
			}
			authorization := "Bearer " + jwt

			res, err := iimpClient.MessageFederation(ctx, iimp_go_client.MessageFederationRequest{
				ConversationId: conversation.Id.Hex(),
				Auth: iimp_go_client.MessageFederationRequestAuthParams{
					Authorization: &authorization,
				},
				Body: messageFederationRequestBody,
			})
			if err != nil {
				return fmt.Errorf("failed to federate message to server '%s': %w", domain, err)
			} else if res.StatusCode != 200 {
				logger.Error.Printf("Failed to federate message to server '%s': %v", domain, err)
				return fmt.Errorf("failed to federate message to server '%s': %w", domain, err)
			}
		}
	}
	return nil
}

func createMessageBroadcastRequestBody(message *dbmodels.Message, conversation *dbmodels.Conversation) iimp_go_client.MessageFederationRequestBody {
	reqBody := iimp_go_client.MessageFederationRequestBody{
		MessageId:        message.Id.Hex(),
		ConversationId:   conversation.Id.Hex(),
		SenderUserId:     message.SenderUserId,
		IsRedacted:       message.IsRedacted,
		Timestamp:        message.Id.Timestamp().Format(time.RFC3339),
		UserSpecificData: make([]iimp_go_client.MessageFederationRequestBodyUserSpecificDataItem, len(message.UserSpecificData)),
		Attachments:      make([]iimp_go_client.MessageFederationRequestBodyAttachmentsItem, len(message.Attachments)),
		Contents:         make([]iimp_go_client.MessageFederationRequestBodyContentsItem, len(message.Contents)),
	}
	for i, usd := range message.UserSpecificData {
		var readAt *string
		if usd.ReadAt != nil {
			t := usd.ReadAt.Time().Format(time.RFC3339)
			readAt = &t
		}
		var reaction *string
		if usd.Reaction != nil {
			reaction = usd.Reaction
		}
		var reactedAt *string
		if usd.ReactedAt != nil {
			t := usd.ReactedAt.Time().Format(time.RFC3339)
			reactedAt = &t
		}
		reqBody.UserSpecificData[i] = iimp_go_client.MessageFederationRequestBodyUserSpecificDataItem{
			RecipientId: usd.RecipientId,
			ReadAt:      readAt,
			Reaction:    reaction,
			ReactedAt:   reactedAt,
		}
	}
	for i, attachment := range message.Attachments {
		reqBody.Attachments[i] = iimp_go_client.MessageFederationRequestBodyAttachmentsItem{
			FileId:          attachment.FileId.Hex(),
			Filename:        attachment.Filename,
			ContentType:     attachment.ContentType,
			Size:            float64(attachment.Size),
			FileHash:        attachment.FileHash,
			AttachmentNonce: attachment.AttachmentNonce,
		}
	}
	for i, content := range message.Contents {
		reqMessageEncryptionData := make([]iimp_go_client.MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem, len(content.MessageContent.EncryptionData))
		for j, ed := range content.MessageContent.EncryptionData {
			reqMessageEncryptionData[j] = iimp_go_client.MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItem{
				RecipientId: ed.RecipientId,
				Encryption: iimp_go_client.MessageFederationRequestBodyContentsItemMessageContentEncryptionDataItemEncryption{
					KeyId:              ed.Encryption.KeyId,
					EncryptedKey:       ed.Encryption.EncryptedKey,
					EphemeralPublicKey: ed.Encryption.EphemeralPublicKey,
					EncryptedKeyNonce:  ed.Encryption.EncryptedKeyNonce,
				},
			}
		}
		reqBody.Contents[i] = iimp_go_client.MessageFederationRequestBodyContentsItem{
			Version: float64(content.Version),
			MessageContent: iimp_go_client.MessageFederationRequestBodyContentsItemMessageContent{
				Content:        content.MessageContent.Content,
				Nonce:          content.MessageContent.Nonce,
				Timestamp:      content.MessageContent.Timestamp.Time().Format(time.RFC3339),
				EncryptionData: reqMessageEncryptionData,
			},
		}
	}
	return reqBody
}
