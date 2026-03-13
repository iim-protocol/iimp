/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"github.com/spf13/cobra"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// newCmd represents the new command
var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Start a new conversation",
	RunE: func(cmd *cobra.Command, args []string) error {
		var isDM bool

		if err := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[bool]().Title("What kind of conversation?").Options(
					huh.NewOption("DM", true),
					huh.NewOption("Group", false),
				).Value(&isDM),
			),
		).Run(); err != nil {
			return fmt.Errorf("failed to start new conversation: %w", err)
		}

		if isDM {
			return createDM(cmd)
		}
		return createGroup(cmd)
	},
}

func init() {
	conversationsCmd.AddCommand(newCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// newCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// newCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func createDM(cmd *cobra.Command) error {
	iimpClient := iimp_go_client.NewIIMP(dbmodels.IIMPSession.ServerUrl)

	var recipientId string
	if err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Recipient User ID (e.g. alice@example.com)").
				Value(&recipientId).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("recipient ID cannot be empty")
					}
					if !strings.Contains(s, "@") || len(strings.Split(s, "@")) != 2 {
						return fmt.Errorf("invalid user ID format")
					}
					return nil
				}),
		),
	).Run(); err != nil {
		return fmt.Errorf("failed to get recipient ID: %w", err)
	}

	authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
	result, err := iimpClient.NewConversation(cmd.Context(), iimp_go_client.NewConversationRequest{
		Auth: iimp_go_client.NewConversationRequestAuthParams{
			Authorization: &authorization,
		},
		Body: iimp_go_client.NewConversationRequestBody{
			ConversationName:   nil,                                                // No name for DM
			ParticipantUserIds: []string{recipientId, dbmodels.IIMPSession.UserId}, // self + recipient
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create conversation: %w", err)
	} else if result.StatusCode != 201 {
		return fmt.Errorf("conversation creation failed with status code: %d", result.StatusCode)
	}

	// save the conversation locally
	conversation, err := convertResponseToConversationModel(result.Response201.Body.Conversation)
	if err != nil {
		return fmt.Errorf("failed to convert conversation model: %w", err)
	}

	err = dbmodels.SaveConversation(conversation)
	if err != nil {
		return fmt.Errorf("failed to save conversation locally: %w", err)
	}
	fmt.Println("Conversation created successfully with ID:", result.Response201.Body.Conversation.ConversationId)
	return nil
}

func createGroup(cmd *cobra.Command) error {
	var conversationName, recipientIdsStr string

	if err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Group Conversation Name").
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("conversation name cannot be empty")
					}
					return nil
				}).Value(&conversationName),
			huh.NewText().
				Title("Participant User IDs").
				Placeholder("one per line, e.g. alice@example.com").Validate(func(s string) error {
				s = strings.ReplaceAll(s, "\r\n", "\n") // handle Windows line endings
				lines := strings.SplitSeq(s, "\n")
				for line := range lines {
					trimmed := strings.TrimSpace(line)
					if trimmed == "" {
						continue
					}
					if !strings.Contains(trimmed, "@") || len(strings.Split(trimmed, "@")) != 2 {
						return fmt.Errorf("invalid user ID format: %s", trimmed)
					}
				}
				return nil
			}).Value(&recipientIdsStr),
		),
	).Run(); err != nil {
		return fmt.Errorf("failed to get group conversation name: %w", err)
	}

	recipientIdsStr = strings.ReplaceAll(recipientIdsStr, "\r\n", "\n") // handle Windows line endings
	recipientIds := strings.Split(recipientIdsStr, "\n")
	iimpClient := iimp_go_client.NewIIMP(dbmodels.IIMPSession.ServerUrl)
	authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
	result, err := iimpClient.NewConversation(cmd.Context(), iimp_go_client.NewConversationRequest{
		Auth: iimp_go_client.NewConversationRequestAuthParams{
			Authorization: &authorization,
		},
		Body: iimp_go_client.NewConversationRequestBody{
			ConversationName:   &conversationName,
			ParticipantUserIds: append(recipientIds, dbmodels.IIMPSession.UserId), // self + others
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create conversation: %w", err)
	} else if result.StatusCode != 201 {
		return fmt.Errorf("conversation creation failed with status code: %d", result.StatusCode)
	}

	// save the conversation locally
	conversation, err := convertResponseToConversationModel(result.Response201.Body.Conversation)
	if err != nil {
		return fmt.Errorf("failed to convert conversation model: %w", err)
	}

	err = dbmodels.SaveConversation(conversation)
	if err != nil {
		return fmt.Errorf("failed to save conversation locally: %w", err)
	}
	fmt.Println("Conversation created successfully with ID:", result.Response201.Body.Conversation.ConversationId)
	return nil
}

func convertResponseToConversationModel(conv iimp_go_client.NewConversation201ResponseBodyConversation) (*dbmodels.Conversation, error) {
	conversation := &dbmodels.Conversation{}

	// transform API response to local conversation model
	conversationIdBson, err := bson.ObjectIDFromHex(conv.ConversationId)
	if err != nil {
		return nil, fmt.Errorf("failed to convert conversation ID to BSON ObjectID: %w", err)
	}
	conversation.Id = conversationIdBson

	conversationName := ""
	if conv.ConversationName != nil {
		conversationName = *conv.ConversationName
	}
	conversation.Name = conversationName

	conversation.IsDM = conv.IsDM
	conversation.OwnerId = conv.ConversationOwnerId
	conversation.Participants = make([]dbmodels.ConversationParticipant, len(conv.Participants))
	for i, p := range conv.Participants {
		joinedAt, err := time.Parse(time.RFC3339, p.JoinedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse participant joinedAt time: %w", err)
		}
		var removedAt *bson.DateTime
		if p.RemovedAt != nil {
			removedAtParsed, err := time.Parse(time.RFC3339, *p.RemovedAt)
			if err != nil {
				return nil, fmt.Errorf("failed to parse participant removedAt time: %w", err)
			}
			removedAtBson := bson.NewDateTimeFromTime(removedAtParsed)
			removedAt = &removedAtBson
		}
		conversation.Participants[i] = dbmodels.ConversationParticipant{
			UserId:          p.UserId,
			UserDisplayName: p.UserDisplayName,
			JoinedAt:        bson.NewDateTimeFromTime(joinedAt),
			RemovedAt:       removedAt,
		}
	}

	return conversation, nil
}
