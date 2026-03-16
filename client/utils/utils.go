package utils

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/iim-protocol/iimp/client/e2e"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
)

func ExtractDomainFromUserId(userId string) (string, error) {
	parts := strings.Split(userId, "@")
	if len(parts) != 2 {
		return "", errors.New("invalid user id format")
	}
	return parts[1], nil
}

func SyncOnce(ctx context.Context, prettyPrint bool) error {
	iimpClient := iimp_go_client.NewIIMP(dbmodels.IIMPSession.ServerUrl)
	authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
	totalEvents := 0

	if prettyPrint {
		fmt.Println("Syncing...")
	}

	reqAuth := iimp_go_client.PullUserEventsRequestAuthParams{
		Authorization: &authorization,
	}

	for {
		cursor, err := dbmodels.GetCursor()
		if err != nil {
			return fmt.Errorf("failed to get cursor: %w", err)
		}

		req := iimp_go_client.PullUserEventsRequest{
			Auth: reqAuth,
		}

		if cursor != "" {
			req.Cursor = &cursor
		}

		if cursor == "" {
			maxLimit := 100.0
			req.Limit = &maxLimit
		}

		result, err := iimpClient.PullUserEvents(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to pull events: %w", err)
		}
		if result.StatusCode != 200 {
			return fmt.Errorf("failed to pull events: status %d", result.StatusCode)
		}

		for _, event := range result.Response200.Body.Events {
			if err := processEvent(event); err != nil {
				return fmt.Errorf("failed to process event %s: %w", event.EventId, err)
			}
			totalEvents++
			if prettyPrint {
				fmt.Printf("\r  processed %d events...", totalEvents)
			}
		}

		if len(result.Response200.Body.Events) > 0 {
			lastEventId := result.Response200.Body.Events[len(result.Response200.Body.Events)-1].EventId
			if err := dbmodels.SaveCursor(lastEventId); err != nil {
				return fmt.Errorf("failed to save cursor: %w", err)
			}
		}

		if result.Response200.Body.NextCursor == nil || *result.Response200.Body.NextCursor == "" {
			if prettyPrint {
				fmt.Printf("\nSync complete! Total events processed: %d\n", totalEvents)
			}
			break
		}
	}

	return nil
}

func processEvent(event iimp_go_client.PullUserEvents200ResponseBodyEventsItem) error {
	switch event.EventType {
	case dbmodels.UserEventTypeConversationUpsert:
		if event.Payload == nil {
			return fmt.Errorf("missing conversation payload")
		}
		payloadStr, ok := (*event.Payload)["conversation"].(string)
		if !ok || payloadStr == "" {
			return fmt.Errorf("conversation payload is not a string or is empty")
		}
		var conversation dbmodels.Conversation
		if err := json.Unmarshal([]byte(payloadStr), &conversation); err != nil {
			return fmt.Errorf("failed to unmarshal conversation upsert payload: %w", err)
		}
		if err := dbmodels.SaveConversation(&conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}

	case dbmodels.UserEventTypeMessageUpsert:
		if event.Payload == nil {
			return fmt.Errorf("missing message payload")
		}
		payloadStr, ok := (*event.Payload)["message"].(string)
		if !ok || payloadStr == "" {
			return fmt.Errorf("message payload is not a string or is empty")
		}
		var message dbmodels.Message
		if err := json.Unmarshal([]byte(payloadStr), &message); err != nil {
			return fmt.Errorf("failed to unmarshal message upsert payload: %w", err)
		}
		if err := dbmodels.SaveMessage(&message); err != nil {
			return fmt.Errorf("failed to save message: %w", err)
		}
	default:
		fmt.Printf("Unhandled event type: %s\n", event.EventType)
	}
	return nil
}

func ComputeSHA256(bytes []byte) string {
	hash := sha256.Sum256(bytes)
	return string(hash[:])
}

func GetMsgPlaintext(content dbmodels.MsgContent, ownUserId string) (string, *time.Time) {
	plaintext := "[encrypted]"
	// find own encryption data
	for _, ed := range content.EncryptionData {
		if ed.RecipientId == ownUserId {
			// decrypt
			keys := dbmodels.LocalUserKeyPairs[ed.Encryption.KeyId]
			if keys != nil {
				privKey, err := keys.GetPrivateKey()
				if err == nil {
					decrypted, err := e2e.DecryptMessage(
						content.Content,
						content.Nonce,
						MapEncryptionData(content.EncryptionData),
						ownUserId,
						privKey,
					)
					if err == nil {
						plaintext = decrypted
					}
				}
			}
			break
		}
	}
	timestamp := content.Timestamp.Time()
	return plaintext, &timestamp
}

func FormatSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(size)/(1024*1024))
}

func MapEncryptionData(data []dbmodels.MessageEncryptionData) []e2e.RecipientEncryptionData {
	result := make([]e2e.RecipientEncryptionData, len(data))
	for i, d := range data {
		result[i] = e2e.RecipientEncryptionData{
			RecipientId:        d.RecipientId,
			KeyId:              d.Encryption.KeyId,
			EphemeralPublicKey: d.Encryption.EphemeralPublicKey,
			EncryptedKey:       d.Encryption.EncryptedKey,
			EncryptedKeyNonce:  d.Encryption.EncryptedKeyNonce,
		}
	}
	return result
}

func ReverseMapEncryptionData(data []e2e.RecipientEncryptionData) []dbmodels.MessageEncryptionData {
	result := make([]dbmodels.MessageEncryptionData, len(data))
	for i, red := range data {
		result[i] = dbmodels.MessageEncryptionData{
			RecipientId: red.RecipientId,
			Encryption: dbmodels.MessageEncryption{
				KeyId:              red.KeyId,
				EncryptedKey:       red.EncryptedKey,
				EncryptedKeyNonce:  red.EncryptedKeyNonce,
				EphemeralPublicKey: red.EphemeralPublicKey,
			},
		}
	}
	return result
}

func FetchRecipientPublicKeys(ctx context.Context, conversation dbmodels.Conversation) ([]e2e.RecipientPublicKey, error) {
	participants := conversation.Participants
	eligibleParticipants := slices.DeleteFunc(participants, func(a dbmodels.ConversationParticipant) bool {
		return a.RemovedAt != nil
	})
	recipientPublicKeys := make([]e2e.RecipientPublicKey, len(eligibleParticipants))

	for i, ep := range eligibleParticipants {
		domain, err := ExtractDomainFromUserId(ep.UserId)
		if err != nil {
			return nil, fmt.Errorf("failed to extract domain from user id (%s): %w", ep.UserId, err)
		}
		baseUrl := "https://" + domain
		iimpClient := iimp_go_client.NewIIMP(baseUrl)
		result, err := iimpClient.GetUserPublicKey(ctx, iimp_go_client.GetUserPublicKeyRequest{
			UserId: ep.UserId,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to fetch public key for user id (%s): %w", ep.UserId, err)
		} else if result.StatusCode != 200 {
			return nil, fmt.Errorf("failed to fetch public key for user id (%s) with status code: %v", ep.UserId, result.StatusCode)
		}

		recipientPublicKeys[i] = e2e.RecipientPublicKey{
			RecipientId:     ep.UserId,
			KeyId:           result.Response200.Body.KeyId,
			PublicKeyBase64: result.Response200.Body.PublicKey,
		}
	}
	return recipientPublicKeys, nil
}

func MapEncryptionDataToNewMessageRequestBodyMessageContentEncryptionDataItem(data []e2e.RecipientEncryptionData) []iimp_go_client.NewMessageRequestBodyMessageContentEncryptionDataItem {
	result := make([]iimp_go_client.NewMessageRequestBodyMessageContentEncryptionDataItem, len(data))
	for i, d := range data {
		result[i] = iimp_go_client.NewMessageRequestBodyMessageContentEncryptionDataItem{
			RecipientId: d.RecipientId,
			Encryption: iimp_go_client.NewMessageRequestBodyMessageContentEncryptionDataItemEncryption{
				KeyId:              d.KeyId,
				EncryptedKey:       d.EncryptedKey,
				EncryptedKeyNonce:  d.EncryptedKeyNonce,
				EphemeralPublicKey: d.EphemeralPublicKey,
			},
		}
	}
	return result
}

func MapEncryptionDataToEditMessageRequestBodyMessageContentEncryptionDataItem(data []e2e.RecipientEncryptionData) []iimp_go_client.EditMessageRequestBodyMessageContentEncryptionDataItem {
	result := make([]iimp_go_client.EditMessageRequestBodyMessageContentEncryptionDataItem, len(data))
	for i, d := range data {
		result[i] = iimp_go_client.EditMessageRequestBodyMessageContentEncryptionDataItem{
			RecipientId: d.RecipientId,
			Encryption: iimp_go_client.EditMessageRequestBodyMessageContentEncryptionDataItemEncryption{
				KeyId:              d.KeyId,
				EncryptedKey:       d.EncryptedKey,
				EncryptedKeyNonce:  d.EncryptedKeyNonce,
				EphemeralPublicKey: d.EphemeralPublicKey,
			},
		}
	}
	return result
}
