package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"
	"github.com/iim-protocol/iimp/client/e2e"
	"github.com/iim-protocol/iimp/client/utils"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
)

type closeEditMessageModalMsg struct{}

type editMessageModalModel struct {
	conversation dbmodels.Conversation
	message      dbmodels.Message
	textarea     textarea.Model
	baseUrl      string
	width        int
	height       int
	ctx          context.Context
	err          error
}

func newEditMessageModalModel(ctx context.Context, conversation dbmodels.Conversation, message dbmodels.Message, baseUrl string) *editMessageModalModel {
	ta := textarea.New()
	ta.Placeholder = "Edit your message..."
	ta.Prompt = "> "
	ta.SetWidth(50)
	ta.SetHeight(5)
	ta.Focus()
	ta.ShowLineNumbers = false
	maxVersionIndex := 0
	for i, mc := range message.Contents {
		if mc.Version > message.Contents[maxVersionIndex].Version {
			maxVersionIndex = i
		}
	}
	content, _ := utils.GetMsgPlaintext(message.Contents[maxVersionIndex].MessageContent, dbmodels.IIMPSession.UserId)
	ta.SetValue(content)

	return &editMessageModalModel{
		conversation: conversation,
		message:      message,
		textarea:     ta,
		ctx:          ctx,
		baseUrl:      baseUrl,
	}
}

func (m *editMessageModalModel) Init() tea.Cmd {
	return m.textarea.Focus()
}

func (m *editMessageModalModel) Update(msg tea.Msg) (*editMessageModalModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "ctrl+c":
			return m, m.close()
		case "enter":
			editedContent := strings.TrimSpace(m.textarea.Value())
			if len(editedContent) == 0 {
				m.err = fmt.Errorf("message content cannot be empty")
				return m, clearErrorAfter(time.Second * 5)
			}

			return m, m.editMessage(editedContent)
		}
	case errMsg:
		m.err = msg.err
	case clearErrMessage:
		m.err = nil
	}
	var cmd tea.Cmd
	m.textarea, cmd = m.textarea.Update(msg)
	return m, cmd
}

func (m *editMessageModalModel) View() tea.View {
	var sb strings.Builder

	header := "Edit Message (press Enter to save, Esc to cancel):"
	sb.WriteString(headerStyle.Width(m.width).Render(header))
	sb.WriteString("\n")
	sb.WriteString(m.textarea.View())
	sb.WriteString("\n")

	if m.err != nil {
		errorMsg := fmt.Sprintf("Error: %s", m.err.Error())
		sb.WriteString(errorStyle.Width(m.width).Render(errorMsg))
		sb.WriteString("\n")
	}

	return tea.View{
		Content:     modalStyle.Render(sb.String()),
		WindowTitle: "Edit Message",
	}
}

func (m *editMessageModalModel) editMessage(content string) tea.Cmd {
	return func() tea.Msg {
		client := iimp_go_client.NewIIMP(m.baseUrl)
		authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
		recipientPublicKeys, err := utils.FetchRecipientPublicKeys(m.ctx, m.conversation)
		if err != nil {
			return errMsg{err: fmt.Errorf("failed to fetch recipient public keys: %w", err)}
		}

		encMessage, err := e2e.EncryptMessage(content, recipientPublicKeys)
		if err != nil {
			return errMsg{err: fmt.Errorf("failed to encrypt message: %w", err)}
		}

		encData := utils.MapEncryptionDataToEditMessageRequestBodyMessageContentEncryptionDataItem(encMessage.EncryptionData)

		req := iimp_go_client.EditMessageRequest{
			ConversationId: m.message.ConversationId.Hex(),
			MessageId:      m.message.Id.Hex(),
			Auth: iimp_go_client.EditMessageRequestAuthParams{
				Authorization: &authorization,
			},
			Body: iimp_go_client.EditMessageRequestBody{
				MessageContent: iimp_go_client.EditMessageRequestBodyMessageContent{
					Content:        encMessage.EncryptedContent,
					Nonce:          encMessage.Nonce,
					EncryptionData: encData,
					Timestamp:      time.Now().Format(time.RFC3339),
				},
			},
		}
		res, err := client.EditMessage(m.ctx, req)
		if err != nil {
			return errMsg{err: fmt.Errorf("failed to edit message: %w", err)}
		}
		if res.StatusCode != 200 {
			return errMsg{err: fmt.Errorf("failed to edit message: status code %d", res.StatusCode)}
		}
		return m.close()
	}
}

func (m *editMessageModalModel) close() tea.Cmd {
	return func() tea.Msg {
		return closeEditMessageModalMsg{}
	}
}
