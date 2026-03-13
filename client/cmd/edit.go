/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/iim-protocol/iimp/client/utils"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"github.com/spf13/cobra"
)

// editCmd represents the edit command
var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit a conversation.",
	RunE: func(cmd *cobra.Command, args []string) error {
		convs, err := dbmodels.ListConversations()
		if err != nil {
			return err
		}

		if len(convs) == 0 {
			return fmt.Errorf("no conversations found. Please start a conversation first.")
		}

		editableConvs := slices.DeleteFunc(convs, func(conv *dbmodels.Conversation) bool {
			return conv.OwnerId != dbmodels.IIMPSession.UserId || conv.IsDM // only allow editing group conversations owned by the user
		})

		if len(editableConvs) == 0 {
			return fmt.Errorf("no editable conversations found. You can only edit group conversations that you own.")
		}

		var conversationId string
		if err := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().Title("Select a conversation to edit").OptionsFunc(func() []huh.Option[string] {
					options := make([]huh.Option[string], len(editableConvs))
					for i, conv := range editableConvs {
						options[i] = huh.NewOption(conv.Name, conv.Id.Hex())
					}
					return options
				}, &conversationId),
			),
		).Run(); err != nil {
			return fmt.Errorf("failed to select conversation: %w", err)
		}

		var editOption EditOption
		if err := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[EditOption]().Title("Select an edit option").
					Options(
						huh.NewOption(string(EditConversationName), EditConversationName),
						huh.NewOption(string(AddConversationParticipants), AddConversationParticipants),
						huh.NewOption(string(RemoveConversationParticipants), RemoveConversationParticipants),
					).Value(&editOption),
			),
		).Run(); err != nil {
			return fmt.Errorf("failed to select edit option: %w", err)
		}

		var selectedConv *dbmodels.Conversation
		idx := slices.IndexFunc(editableConvs, func(conv *dbmodels.Conversation) bool {
			return conv.Id.Hex() == conversationId
		})
		selectedConv = editableConvs[idx] // we know this will succeed because the conversationId options were generated from editableConvs

		switch editOption {
		case EditConversationName:
			return editConversationName(cmd, selectedConv)
		case AddConversationParticipants:
			return addConversationParticipants(cmd, selectedConv)
		case RemoveConversationParticipants:
			return removeConversationParticipants(cmd, selectedConv)
		}
		return fmt.Errorf("invalid edit option selected")
	},
}

func init() {
	conversationsCmd.AddCommand(editCmd)
}

type EditOption string

var (
	EditConversationName           EditOption = "Edit Name"
	AddConversationParticipants    EditOption = "Add Participants"
	RemoveConversationParticipants EditOption = "Remove Participants"
)

func editConversationName(cmd *cobra.Command, conv *dbmodels.Conversation) error {
	if err := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(fmt.Sprintf("Current conversation name: %s", conv.Name)),
			huh.NewInput().Title("New Conversation Name").Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("conversation name cannot be empty")
				}
				return nil
			}).Value(&conv.Name),
		),
	).Run(); err != nil {
		return fmt.Errorf("failed to get new conversation name: %w", err)
	}

	// create a client for conversation owner's server.
	ownerDomain, err := utils.ExtractDomainFromUserId(conv.OwnerId)
	if err != nil {
		return fmt.Errorf("failed to get domain from conversation owner ID: %w", err)
	}
	iimpClient := iimp_go_client.NewIIMP("https://" + ownerDomain)
	authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
	result, err := iimpClient.UpdateConversation(cmd.Context(), iimp_go_client.UpdateConversationRequest{
		Auth: iimp_go_client.UpdateConversationRequestAuthParams{
			Authorization: &authorization,
		},
		ConversationId: conv.Id.Hex(),
		Body: iimp_go_client.UpdateConversationRequestBody{
			ConversationName: &conv.Name,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update conversation: %w", err)
	} else if result.StatusCode != 200 {
		return fmt.Errorf("conversation update failed with status code: %d", result.StatusCode)
	}

	// save the updated conversation locally
	err = dbmodels.SaveConversation(conv)
	if err != nil {
		return fmt.Errorf("failed to save updated conversation locally: %w", err)
	}
	fmt.Println("Conversation name updated successfully.")
	return nil
}

func addConversationParticipants(cmd *cobra.Command, conv *dbmodels.Conversation) error {
	var newRecipientUserIdsStr string

	if err := huh.NewForm(
		huh.NewGroup(
			huh.NewText().Title("User IDs of new participants to add (one per line)").Validate(func(s string) error {
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
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("at least one user ID must be provided")
				}
				return nil
			}).Value(&newRecipientUserIdsStr),
		),
	).Run(); err != nil {
		return fmt.Errorf("failed to get new participant user IDs: %w", err)
	}

	newRecipientUserIdsStr = strings.ReplaceAll(newRecipientUserIdsStr, "\r\n", "\n") // handle Windows line endings
	newRecipientUserIds := strings.Split(newRecipientUserIdsStr, "\n")
	// after splitting
	for i, id := range newRecipientUserIds {
		newRecipientUserIds[i] = strings.TrimSpace(id)
	}
	// filter empty strings
	newRecipientUserIds = slices.DeleteFunc(newRecipientUserIds, func(s string) bool {
		return s == ""
	})

	// create a client for conversation owner's server.
	ownerDomain, err := utils.ExtractDomainFromUserId(conv.OwnerId)
	if err != nil {
		return fmt.Errorf("failed to get domain from conversation owner ID: %w", err)
	}
	iimpClient := iimp_go_client.NewIIMP("https://" + ownerDomain)
	authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
	result, err := iimpClient.UpdateConversation(cmd.Context(), iimp_go_client.UpdateConversationRequest{
		Auth: iimp_go_client.UpdateConversationRequestAuthParams{
			Authorization: &authorization,
		},
		ConversationId: conv.Id.Hex(),
		Body: iimp_go_client.UpdateConversationRequestBody{
			ParticipantUserIdsToAdd: newRecipientUserIds,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add conversation participants: %w", err)
	} else if result.StatusCode != 200 {
		return fmt.Errorf("add conversation participants failed with status code: %d", result.StatusCode)
	}

	// save the updated conversation locally
	err = dbmodels.SaveConversation(conv)
	if err != nil {
		return fmt.Errorf("failed to save updated conversation locally: %w", err)
	}
	fmt.Println("New participants added successfully.")
	return nil
}

func removeConversationParticipants(cmd *cobra.Command, conv *dbmodels.Conversation) error {
	var participantUserIdsToRemoveStr string

	if err := huh.NewForm(
		huh.NewGroup(
			huh.NewText().Title("User IDs of participants to remove (one per line)").Validate(func(s string) error {
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
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("at least one user ID must be provided")
				}
				return nil
			}).Value(&participantUserIdsToRemoveStr),
		),
	).Run(); err != nil {
		return fmt.Errorf("failed to get participant user IDs to remove: %w", err)
	}

	participantUserIdsToRemoveStr = strings.ReplaceAll(participantUserIdsToRemoveStr, "\r\n", "\n") // handle Windows line endings
	participantUserIdsToRemove := strings.Split(participantUserIdsToRemoveStr, "\n")
	// after splitting
	for i, id := range participantUserIdsToRemove {
		participantUserIdsToRemove[i] = strings.TrimSpace(id)
	}
	// filter empty strings
	participantUserIdsToRemove = slices.DeleteFunc(participantUserIdsToRemove, func(s string) bool {
		return s == ""
	})

	// create a client for conversation owner's server.
	ownerDomain, err := utils.ExtractDomainFromUserId(conv.OwnerId)
	if err != nil {
		return fmt.Errorf("failed to get domain from conversation owner ID: %w", err)
	}
	iimpClient := iimp_go_client.NewIIMP("https://" + ownerDomain)
	authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
	result, err := iimpClient.UpdateConversation(cmd.Context(), iimp_go_client.UpdateConversationRequest{
		Auth: iimp_go_client.UpdateConversationRequestAuthParams{
			Authorization: &authorization,
		},
		ConversationId: conv.Id.Hex(),
		Body: iimp_go_client.UpdateConversationRequestBody{
			ParticipantUserIdsToRemove: participantUserIdsToRemove,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to remove conversation participants: %w", err)
	} else if result.StatusCode != 200 {
		return fmt.Errorf("remove conversation participants failed with status code: %d", result.StatusCode)
	}

	// save the updated conversation locally
	err = dbmodels.SaveConversation(conv)
	if err != nil {
		return fmt.Errorf("failed to save updated conversation locally: %w", err)
	}
	fmt.Println("Participants removed successfully.")
	return nil
}
