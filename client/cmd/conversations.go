/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/spf13/cobra"
)

// conversationsCmd represents the conversations command
var conversationsCmd = &cobra.Command{
	Use:   "conversations",
	Short: "List all your conversations",
	Run: func(cmd *cobra.Command, args []string) {
		convs, err := dbmodels.ListConversations()
		if err != nil {
			fmt.Printf("Error loading conversations: %v\n", err)
			return
		}

		if len(convs) == 0 {
			fmt.Println("No conversations found.")
			return
		}

		fmt.Println("Your Conversations:")
		for _, conv := range convs {
			if conv.IsDM {
				otherUserId := getOtherUserId(conv, dbmodels.IIMPSession.UserId)
				otherUserDisplayName := getUserDisplayName(conv, otherUserId)
				fmt.Printf("- [DM] Conversation with %s (%s) \n", otherUserDisplayName, otherUserId)
			} else {
				fmt.Printf("- [Group] %s \n", conv.Name)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(conversationsCmd)
}

// Only for DM conversations
func getOtherUserId(conv *dbmodels.Conversation, selfUserId string) string {
	for _, participant := range conv.Participants {
		if participant.UserId != selfUserId {
			return participant.UserId
		}
	}
	return ""
}

func getUserDisplayName(conv *dbmodels.Conversation, userId string) string {
	for _, participant := range conv.Participants {
		if participant.UserId == userId {
			return participant.UserDisplayName
		}
	}
	return "N/A"
}
