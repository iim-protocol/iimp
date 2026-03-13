/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/huh"
	"github.com/iim-protocol/iimp/client/tui"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"github.com/spf13/cobra"
)

// chatCmd represents the chat command
var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Chat among your conversations",
	RunE: func(cmd *cobra.Command, args []string) error {
		// fetch all conversations
		convs, err := dbmodels.ListConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations: %w", err)
		}

		if len(convs) == 0 {
			return fmt.Errorf("no conversations found. Please start a conversation first.")
		}

		var selectedConversationId string

		// select which conversation to chat in
		convOpts := make([]huh.Option[string], len(convs))
		for idx, conv := range convs {
			convOpts[idx] = huh.NewOption(getConversationName(*conv), conv.Id.Hex())
		}

		if err := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Select a conversation").
					Options(convOpts...).
					Value(&selectedConversationId).
					Validate(func(id string) error {
						if strings.TrimSpace(id) == "" {
							return fmt.Errorf("kindly select a conversation to chat!")
						}
						return nil
					}),
			),
		).Run(); err != nil {
			return fmt.Errorf("form error: %w", err)
		}

		// fetch messages for the selected conversation
		selectedConversationIndex := slices.IndexFunc(convs, func(conv *dbmodels.Conversation) bool {
			return conv.Id.Hex() == selectedConversationId
		})
		messages, err := dbmodels.ListMessages(convs[selectedConversationIndex].Id.Hex())
		if err != nil {
			return fmt.Errorf("failed to load messages: %w", err)
		}

		// show a loading, thingy, while we mark the messages as read using normal \r pattern
		fmt.Print("Loading messages...")
		// mark every message that's not read by the current user as read with the timestamp of now
		timestamp := time.Now().Format(time.RFC3339)
		iimpClient := iimp_go_client.NewIIMP(dbmodels.IIMPSession.ServerUrl)
		authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
		auth := iimp_go_client.ReadMessageRequestAuthParams{
			Authorization: &authorization,
		}
		unreadMessages := slices.DeleteFunc(messages, func(message dbmodels.Message) bool {
			for _, usd := range message.UserSpecificData {
				if usd.RecipientId == dbmodels.IIMPSession.UserId {
					if usd.ReadAt == nil {
						return false
					}
				}
			}
			return true
		})
		lenUnread := len(unreadMessages)
		for idx, message := range unreadMessages {
			res, err := iimpClient.ReadMessage(cmd.Context(), iimp_go_client.ReadMessageRequest{
				ConversationId: selectedConversationId,
				MessageId:      message.Id.Hex(),
				Auth:           auth,
			})
			if err != nil {
				return fmt.Errorf("failed to mark message as read: %w", err)
			}
			if res.StatusCode != 200 {
				return fmt.Errorf("failed to mark message as read: status code %d", res.StatusCode)
			}
			fmt.Printf("\rMarking messages as read (%d/%d)... "+timestamp, idx+1, lenUnread)
			time.Sleep(100 * time.Millisecond) // just to show the loading effect
		}
		fmt.Print("\r                    \r") // clear the loading message

		chatModel := tui.NewChatModel(*convs[selectedConversationIndex], messages)
		teaProgram := tea.NewProgram(chatModel)

		if _, err := teaProgram.Run(); err != nil {
			return fmt.Errorf("bubbletea error: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(chatCmd)
}

func getConversationName(conversation dbmodels.Conversation) string {
	if conversation.IsDM {
		idx := 0
		if conversation.Participants[0].UserId == dbmodels.IIMPSession.UserId {
			idx = 1
		}
		return "DM - " + conversation.Participants[idx].UserDisplayName
	}
	return conversation.Name
}
