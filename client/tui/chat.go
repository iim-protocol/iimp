package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/iim-protocol/iimp/client/e2e"
	"github.com/iim-protocol/iimp/client/utils"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var (
	defaultTextAreaPlaceholder = "Type a message... (shift+enter for new line, enter to send)"
)

type chatModel struct {
	conversation            dbmodels.Conversation
	messages                []dbmodels.Message
	viewport                viewport.Model
	textarea                textarea.Model
	filepicker              filepicker.Model
	downloadAttachmentModal *downloadAttachmentModalModel
	readByModal             *readByModalModel
	reactionsModal          *reactionsModalModel
	messageHistoryModal     *messageHistoryModalModel
	editMessageModal        *editMessageModalModel

	showFilePicker bool // default: false, true when a user wants to select a file
	// absolute paths to the attachments
	showReadByModal             bool
	showReactionsModal          bool
	showDownloadAttachmentModel bool
	showMessageHistoryModal     bool
	showEditMessageModal        bool
	pendingAttachments          []string
	selectedMsgIndex            int // -1 = no selection => textarea focused
	width                       int
	height                      int
	err                         error
	ctx                         context.Context
	cancel                      context.CancelFunc
}

// custom tea messages
type newMessagesMsg struct {
	// all the messages, not just the new ones
	messages []dbmodels.Message
}
type sentMessageOkMsg struct{}
type showFilePickerMsg struct{}
type errMsg struct{ err error }
type clearErrMessage struct{}

func NewChatModel(conv dbmodels.Conversation, messages []dbmodels.Message) chatModel {
	ta := textarea.New()
	ta.Placeholder = defaultTextAreaPlaceholder
	ta.Focus()
	ta.Prompt = "> "
	ta.SetWidth(80)
	ta.SetHeight(2)
	ta.ShowLineNumbers = false

	vp := viewport.New(viewport.WithWidth(80), viewport.WithHeight(20))

	fp := filepicker.New()
	fp.AllowedTypes = []string{".png", ".jpg", ".jpeg", ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".rtf"}
	fp.ShowSize = true
	fp.AutoHeight = true

	home := os.Getenv("HOME")
	if home == "" {
		homeOut = "."
	} else {
		homeOut = home
	}
	fp.CurrentDirectory = homeOut

	ctx, cancel := context.WithCancel(context.Background())

	m := chatModel{
		conversation:                conv,
		messages:                    messages,
		textarea:                    ta,
		viewport:                    vp,
		filepicker:                  fp,
		downloadAttachmentModal:     nil, // initialized when user tries to download an attachment
		showFilePicker:              false,
		showReadByModal:             false,
		showReactionsModal:          false,
		showDownloadAttachmentModel: false,
		selectedMsgIndex:            -1,
		ctx:                         ctx,
		cancel:                      cancel,
	}

	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()

	return m
}

var homeOut string

func (m chatModel) Init() tea.Cmd {
	return tea.Batch(m.filepicker.Init(), m.syncCmd())
}

func (m chatModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	if m.showDownloadAttachmentModel {
		if _, ok := msg.(closeDownloadModalMsg); ok {
			m.downloadAttachmentModal = nil
			m.showDownloadAttachmentModel = false
			return m, nil
		}
		var dmCmd tea.Cmd
		m.downloadAttachmentModal, dmCmd = m.downloadAttachmentModal.Update(msg)
		return m, dmCmd
	}

	if m.showReadByModal {
		var rbCmd tea.Cmd
		if _, ok := msg.(closeReadByModalMsg); ok {
			m.readByModal = nil
			m.showReadByModal = false
			return m, m.syncCmd()
		}
		m.readByModal, rbCmd = m.readByModal.Update(msg)
		return m, rbCmd
	}

	if m.showReactionsModal {
		var rCmd tea.Cmd
		if _, ok := msg.(closeReactionsModalMsg); ok {
			m.reactionsModal = nil
			m.showReactionsModal = false
			return m, m.syncCmd()
		}
		m.reactionsModal, rCmd = m.reactionsModal.Update(msg)
		return m, rCmd
	}

	if m.showEditMessageModal {
		var emCmd tea.Cmd
		if _, ok := msg.(closeEditMessageModalMsg); ok {
			m.editMessageModal = nil
			m.showEditMessageModal = false
			return m, m.syncCmd()
		}
		m.editMessageModal, emCmd = m.editMessageModal.Update(msg)
		return m, emCmd
	}

	if m.showMessageHistoryModal {
		var mhCmd tea.Cmd
		if _, ok := msg.(closeMessageHistoryModalMsg); ok {
			m.messageHistoryModal = nil
			m.showMessageHistoryModal = false
			return m, m.syncCmd()
		}
		m.messageHistoryModal, mhCmd = m.messageHistoryModal.Update(msg)
		return m, mhCmd
	}

	if m.showFilePicker {
		var fpCmd tea.Cmd
		m.filepicker, fpCmd = m.filepicker.Update(msg)

		switch msg := msg.(type) {
		case clearErrMessage:
			m.err = nil
			return m, fpCmd
		case tea.KeyMsg:
			switch msg.String() {
			case "ctrl+c":
				m.showFilePicker = false
				return m, fpCmd
			}
		}

		// handle file selection
		if yes, _ := m.filepicker.DidSelectDisabledFile(msg); yes {
			m.showFilePicker = false
			m.err = fmt.Errorf("You picked a disabled file, please pick a valid file!")
			return m, tea.Batch(fpCmd)
		}

		if yes, path := m.filepicker.DidSelectFile(msg); yes {
			m.pendingAttachments = append(m.pendingAttachments, path)
			m.showFilePicker = false
		}
		return m, fpCmd
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Reserve lines for header (1), error bar (3), pending bar (3), and textarea (3)
		// Adjust these numbers if you add/remove lines elsewhere
		textareaHeight := max(m.textarea.LineCount()+1, 2)
		headerHeight := 1
		errorBarHeight := 2
		pendingBarHeight := 2

		// Calculate available height for viewport
		usedHeight := headerHeight + errorBarHeight + pendingBarHeight + textareaHeight
		viewportHeight := max(m.height-usedHeight,
			// minimum for usability
			3)

		m.viewport.SetWidth(m.width)
		m.viewport.SetHeight(viewportHeight)
		m.textarea.SetWidth(m.width)
		modalStyle = modalStyle.Width(m.width)
		m.textarea.SetHeight(textareaHeight)
		m.viewport.SetContent(m.renderMessages())
		m.filepicker.SetHeight(m.height - int(float64(m.height)*0.1))

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			if m.showReactionsModal {
				m.showReactionsModal = false
				return m, nil
			}
			return m, tea.Quit

		case "up":
			if m.selectedMsgIndex == -1 {
				// leave textarea, start selecting messages
				m.textarea.Blur()
				m.selectedMsgIndex = len(m.messages) - 1
			} else if m.selectedMsgIndex > 0 {
				m.selectedMsgIndex--
			}
			m.viewport.SetContent(m.renderMessages())

		case "down":
			if m.selectedMsgIndex != -1 {
				if m.selectedMsgIndex < len(m.messages)-1 {
					m.selectedMsgIndex++
				} else {
					// back to textarea
					m.selectedMsgIndex = -1
					m.textarea.Focus()
				}
			}
			m.viewport.SetContent(m.renderMessages())

		case "esc":
			if m.selectedMsgIndex != -1 {
				m.selectedMsgIndex = -1
				m.textarea.Focus()
				m.viewport.SetContent(m.renderMessages())
			}

		case "enter":
			if m.selectedMsgIndex == -1 {
				content := strings.TrimSpace(m.textarea.Value())
				if content == "" && len(m.pendingAttachments) == 0 {
					break
				}

				if content == "" && len(m.pendingAttachments) != 0 {
					content = dbmodels.IIMPSession.UserId + " shared attachments!"
				}

				cmds = append(cmds, m.sendMessageCmd(content, slices.Clone(m.pendingAttachments)))
			}

		case "ctrl+a":
			// attach file - launch the huh file picker
			// show file picker
			cmds = append(cmds, m.attachFileCmd())
		case "ctrl+d":
			// download attachment from selected message
			if m.selectedMsgIndex != -1 && len(m.messages[m.selectedMsgIndex].Attachments) > 0 {
				m.showDownloadAttachmentModel = true
				domain, err := utils.ExtractDomainFromUserId(m.conversation.OwnerId)
				if err != nil {
					m.err = fmt.Errorf("error extracting domain: %w", err)
					return m, clearErrorAfter(time.Second * 5)
				}
				baseUrl := "https://" + domain
				dm := newDownloadAttachmentModalModel(m.ctx, m.messages[m.selectedMsgIndex], baseUrl)
				m.downloadAttachmentModal = &dm
				return m, m.downloadAttachmentModal.Init()
			}
		case "ctrl+r":
			// show read by modal for selected message
			if m.selectedMsgIndex != -1 {
				m.showReadByModal = true
				m.readByModal = newReadByModalModel(m.messages[m.selectedMsgIndex])
				return m, m.readByModal.Init()
			}
		case "ctrl+o":
			// show reactions modal for selected message
			if m.selectedMsgIndex != -1 {
				m.showReactionsModal = true
				domain, err := utils.ExtractDomainFromUserId(m.conversation.OwnerId)
				if err != nil {
					m.err = fmt.Errorf("error extracting domain: %w", err)
					return m, clearErrorAfter(time.Second * 5)
				}
				baseUrl := "https://" + domain
				m.reactionsModal = newReactionsModalModel(m.ctx, m.messages[m.selectedMsgIndex], baseUrl)
				return m, m.reactionsModal.Init()
			}
		case "ctrl+h":
			// show message history modal for selected message
			if m.selectedMsgIndex != -1 {
				m.showMessageHistoryModal = true
				m.messageHistoryModal = newMessageHistoryModalModel(m.messages[m.selectedMsgIndex])
				return m, m.messageHistoryModal.Init()
			}
		case "ctrl+e":
			// show edit message modal for selected message
			if m.selectedMsgIndex != -1 {
				if m.messages[m.selectedMsgIndex].SenderUserId != dbmodels.IIMPSession.UserId {
					m.err = fmt.Errorf("you can only edit your own messages")
					cmds = append(cmds, clearErrorAfter(time.Second*5))
				} else {
					m.showEditMessageModal = true
					domain, err := utils.ExtractDomainFromUserId(m.conversation.OwnerId)
					if err != nil {
						m.err = fmt.Errorf("error extracting domain: %w", err)
						cmds = append(cmds, clearErrorAfter(time.Second*5))
					} else {
						baseUrl := "https://" + domain
						m.editMessageModal = newEditMessageModalModel(m.ctx, m.conversation, m.messages[m.selectedMsgIndex], baseUrl)
						return m, m.editMessageModal.Init()
					}
				}
			}
		case "ctrl+x":
			if len(m.pendingAttachments) > 0 {
				m.pendingAttachments = nil
			}
		}

	case showFilePickerMsg:
		// do nothing
		m.showFilePicker = true
		return m, nil

	case newMessagesMsg:
		// Do a full replace as the newMessagesMsg will always have
		// a full list of messages
		m.messages = msg.messages
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()
		cmds = append(cmds, tickCmd(time.Second*5, m.syncCmd()))

	case sentMessageOkMsg:
		// Reset state
		m.textarea.Reset()
		m.pendingAttachments = nil
		m.err = nil
		cmds = append(cmds, m.syncCmd())

	case errMsg:
		m.err = msg.err
		cmds = append(cmds, clearErrorAfter(time.Second*5))
	case clearErrMessage:
		m.err = nil
	}

	var cmd tea.Cmd
	if m.selectedMsgIndex == -1 {
		m.textarea, cmd = m.textarea.Update(msg)
		cmds = append(cmds, cmd)
	}
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)
	if _, ok := msg.(tea.KeyMsg); !ok {
		var fpCmd tea.Cmd
		m.filepicker, fpCmd = m.filepicker.Update(msg)
		cmds = append(cmds, fpCmd)
	}

	return m, tea.Batch(cmds...)
}

func (m chatModel) View() tea.View {
	if m.showReadByModal {
		return m.readByModal.View()
	}
	if m.showReactionsModal {
		return m.reactionsModal.View()
	}
	if m.showDownloadAttachmentModel {
		return m.downloadAttachmentModal.View()
	}
	if m.showMessageHistoryModal {
		return m.messageHistoryModal.View()
	}
	if m.showEditMessageModal {
		return m.editMessageModal.View()
	}
	if m.showFilePicker {
		var s strings.Builder
		s.WriteString("  ")

		s.WriteString("HomeOut: " + homeOut)
		s.WriteString("CurrentDirectory: " + m.filepicker.CurrentDirectory)

		header := lipgloss.NewStyle().Bold(true).Padding(0, 1).Width(m.width).Render("Select a file to attach [arrow keys to navigate] [enter to select] [ctrl+c to cancel]")

		s.WriteString(header)
		s.WriteString("\n")

		s.WriteString(m.filepicker.View())
		s.WriteString("\n")

		return tea.View{
			Content:     s.String(),
			WindowTitle: "Select a file to attach",
			AltScreen:   true,
		}
	}
	content := ""

	// Add the header
	header := headerStyle.
		Width(m.width).
		Render(fmt.Sprintf("%s [ctrl+c quit] [↑↓ select] [ctrl+a attach] [ctrl+d download]", m.getConversationName()))

	content += header
	content += "\n"

	// Add the error bar
	errBar := ""
	if m.err != nil {
		// fmt.Fprintf(os.Stderr, "DEBUG: m.err = %v\n", m.err)
		errBar = errorStyle.Render(fmt.Sprintf("⚠️  %s", m.err.Error())) + "\n"
	}
	content += errBar
	if errBar != "" {
		content += "\n"
	}

	// add viewport
	content += m.viewport.View()
	content += "\n"

	// Add the pending attachments bar
	pendingBar := ""
	if len(m.pendingAttachments) > 0 {
		names := make([]string, len(m.pendingAttachments))
		for i, a := range m.pendingAttachments {
			names[i] = pendingStyle.Render(fmt.Sprintf("📎 %s", path.Base(a)))
		}
		pendingBar = strings.Join(names, "  ") + "  [ctrl+x to remove]\n"
	}
	content += pendingBar
	content += "\n"

	// Add the textarea
	content += m.textarea.View()

	return tea.View{
		Content:     content,
		WindowTitle: m.conversation.Name,
	}
}

func (m chatModel) renderMessages() string {
	if len(m.messages) == 0 {
		return timestampStyle.Render("No messages yet. Say hello!")
	}

	var sb strings.Builder

	ownUserId := dbmodels.IIMPSession.UserId

	for i, msg := range m.messages {
		// get the latest message content
		latestContent := getLatestContent(msg)

		plaintext := "[encrypted]"
		var latestTimestamp *time.Time
		if latestContent != nil {
			plaintext, latestTimestamp = utils.GetMsgPlaintext(latestContent.MessageContent, ownUserId)
		}

		// build message block
		isSelected := i == m.selectedMsgIndex
		isOwn := msg.SenderUserId == ownUserId
		timestamp := msg.Id.Timestamp().Format(time.DateTime)

		var block strings.Builder

		// sender + timestamp line
		sender := ""
		if isOwn {
			sender = ownStyle.Render("You")
		} else {
			sender = senderStyle.Render(m.getUserName(msg.SenderUserId))
		}
		senderLine := fmt.Sprintf("%s  %s",
			sender,
			timestampStyle.Render(timestamp),
		)
		if msg.IsRedacted {
			senderLine += " [redacted]"
		} else if len(msg.Contents) > 1 {
			editedLine := ""
			if latestTimestamp != nil {
				editedLine = fmt.Sprintf("[edited - %s]", latestTimestamp.Format(time.DateTime))
			} else {
				editedLine = "[edited]"
			}
			senderLine += " " + editedStyle.Render(editedLine)
		}
		if isOwn {
			block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Right).Render(senderLine) + "\n")
		} else {
			block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Left).Render(senderLine) + "\n")
		}

		// content
		if msg.IsRedacted {
			content := timestampStyle.Render("🗑️ This message was redacted")
			if isOwn {
				block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Right).Render(content) + "\n")
			} else {
				block.WriteString("  " + content + "\n")
			}
		} else {
			if isOwn {
				block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Right).Render(plaintext) + "\n")
			} else {
				block.WriteString("  " + plaintext + "\n")
			}

			// attachments
			for _, att := range msg.Attachments {
				attLine := attachStyle.Render(fmt.Sprintf("  📎 %s (%s)", att.Filename, utils.FormatSize(att.Size)))
				if isOwn {
					block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Right).Render(attLine) + "\n")
				} else {
					block.WriteString(attLine + "\n")
				}
			}
		}

		// reaction
		readByCount := 0
		for _, usd := range msg.UserSpecificData {
			if usd.Reaction != nil {
				reactionLine := fmt.Sprintf("  %s %s", *usd.Reaction, timestampStyle.Render(m.getUserName(usd.RecipientId)))
				if isOwn {
					block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Right).Render(reactionLine + "\n"))
				} else {
					block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Left).Render(reactionLine + "\n"))
				}
				block.WriteString(",")
			}
			if usd.ReadAt != nil {
				readByCount++
			}
		}
		if readByCount > 0 {
			readByLine := fmt.Sprintf("Read by %d users", readByCount)
			if isOwn {
				block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Right).Render(readByLine + "\n"))
			} else {
				block.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Left).Render(readByLine + "\n"))
			}
		}

		rendered := block.String()
		if isSelected {
			rendered = selectedStyle.Render(rendered)
		}

		sb.WriteString(rendered)
		sb.WriteString("\n")
	}

	return sb.String()
}

// tea commands for the chat model
func (m chatModel) syncCmd() tea.Cmd {
	return func() tea.Msg {
		if err := utils.SyncOnce(m.ctx, false); err != nil {
			return errMsg{err: fmt.Errorf("sync error: %w", err)}
		}
		messages, err := dbmodels.ListMessages(m.conversation.Id.Hex())
		if err != nil {
			return errMsg{err: fmt.Errorf("message loading error: %w", err)}
		}
		return newMessagesMsg{messages: messages}
	}
}

func (m chatModel) sendMessageCmd(content string, pendingAttachments []string) tea.Cmd {
	return func() tea.Msg {
		domain, err := utils.ExtractDomainFromUserId(m.conversation.OwnerId)
		if err != nil {
			return errMsg{err: fmt.Errorf("error extracting domain: %w", err)}
		}
		baseUrl := "https://" + domain
		iimpClient := iimp_go_client.NewIIMP(baseUrl)
		authorization := "Bearer " + dbmodels.IIMPSession.AccessToken

		// encrypt message
		publicKeys, err := utils.FetchRecipientPublicKeys(m.ctx, m.conversation)
		if err != nil {
			return errMsg{err: fmt.Errorf("error fetching public key: %w", err)}
		}
		encMsg, err := e2e.EncryptMessage(content, publicKeys)
		if err != nil {
			return errMsg{err: fmt.Errorf("error encrypting message: %w", err)}
		}

		encData := utils.MapEncryptionDataToNewMessageRequestBodyMessageContentEncryptionDataItem(encMsg.EncryptionData)

		reqBody := iimp_go_client.NewMessageRequestBody{
			MessageContent: iimp_go_client.NewMessageRequestBodyMessageContent{
				Content:        encMsg.EncryptedContent,
				Nonce:          encMsg.Nonce,
				Timestamp:      time.Now().Format(time.RFC3339),
				EncryptionData: encData,
			},
		}

		if len(pendingAttachments) > 0 {
			attachments := make([]iimp_go_client.NewMessageRequestBodyAttachmentsItem, len(pendingAttachments))
			for i, a := range pendingAttachments {
				// upon selection, the file id will not have been populated.
				// first, we need to upload the file bytes, which will provide us a fileId
				// which we have to give here.

				pendingAttachment, err := uploadAttachment(m.ctx, baseUrl, a, encMsg.SymmetricKey)
				if err != nil {
					return errMsg{err: fmt.Errorf("failed to upload attachment: %w", err)}
				}

				attachments[i] = iimp_go_client.NewMessageRequestBodyAttachmentsItem{
					FileId:          pendingAttachment.FileId.Hex(),
					Filename:        pendingAttachment.Filename,
					ContentType:     pendingAttachment.ContentType,
					Size:            float64(pendingAttachment.Size),
					FileHash:        pendingAttachment.FileHash,
					AttachmentNonce: pendingAttachment.AttachmentNonce,
				}
			}
			reqBody.Attachments = attachments
		}

		result, err := iimpClient.NewMessage(m.ctx, iimp_go_client.NewMessageRequest{
			ConversationId: m.conversation.Id.Hex(),
			Auth: iimp_go_client.NewMessageRequestAuthParams{
				Authorization: &authorization,
			},
			Body: reqBody,
		})
		if err != nil {
			return errMsg{err: fmt.Errorf("error sending message: %w", err)}
		}
		if result.StatusCode != 201 {
			return errMsg{err: fmt.Errorf("failed to send message, status code: %d", result.StatusCode)}
		}
		return sentMessageOkMsg{}
	}
}

func (m chatModel) attachFileCmd() tea.Cmd {
	return tea.Sequence(
		func() tea.Msg {
			home := os.Getenv("HOME")
			homeOut = home
			if home == "" {
				m.filepicker.CurrentDirectory = "."
			} else {
				m.filepicker.CurrentDirectory = home
			}
			return nil
		},
		m.filepicker.Init(),
		func() tea.Msg {
			return showFilePickerMsg{}
		},
	)
}

func getLatestContent(msg dbmodels.Message) *dbmodels.MessageContentItem {
	if len(msg.Contents) == 0 {
		return nil
	}

	latest := &msg.Contents[0]
	for i := range msg.Contents {
		if msg.Contents[i].Version > latest.Version {
			latest = &msg.Contents[i]
		}
	}
	return latest
}

func (m chatModel) getUserName(userId string) string {
	for _, participant := range m.conversation.Participants {
		if participant.UserId == userId {
			return participant.UserDisplayName
		}
	}
	return userId
}

func (m chatModel) getConversationName() string {
	if m.conversation.IsDM {
		idx := 0
		if m.conversation.Participants[0].UserId == dbmodels.IIMPSession.UserId {
			idx = 1
		}
		return "DM - " + m.conversation.Participants[idx].UserDisplayName
	}
	return m.conversation.Name
}

func uploadAttachment(ctx context.Context, baseUrl, filePath string, symmetricKey []byte) (dbmodels.Attachment, error) {
	// encrypt attachment first
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return dbmodels.Attachment{}, fmt.Errorf("failed to read file (%s): %w", filePath, err)
	}
	encAttach, err := e2e.EncryptAttachment(fileBytes, symmetricKey)
	if err != nil {
		return dbmodels.Attachment{}, fmt.Errorf("failed to encrypt attachment: %w", err)
	}
	filename := path.Base(filePath)

	// upload the file using the iimp client information
	// cannot use client directly since it doesn't support byte bodies/raw bodies
	url := baseUrl + iimp_go_client.UploadAttachmentRequestRoutePath
	r, err := http.NewRequestWithContext(ctx, iimp_go_client.UploadAttachmentRequestHTTPMethod, url, bytes.NewReader(encAttach.EncryptedBytes))
	if err != nil {
		return dbmodels.Attachment{}, fmt.Errorf("failed to create upload attachment request: %w", err)
	}
	r.Header.Set("Authorization", "Bearer "+dbmodels.IIMPSession.AccessToken)
	r.Header.Set("X-IIMP-Attachment-Filename", filename)
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		return dbmodels.Attachment{}, fmt.Errorf("failed to upload attachment: %w", err)
	}
	if response.StatusCode != 201 {
		// upload failed
		return dbmodels.Attachment{}, fmt.Errorf("failed to upload attachment with status code: %v", response.StatusCode)
	}

	body := iimp_go_client.UploadAttachment201ResponseBody{}
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return dbmodels.Attachment{}, fmt.Errorf("failed to decode response body: %w", err)
	}
	err = json.Unmarshal(bodyBytes, &body)
	if err != nil {
		return dbmodels.Attachment{}, fmt.Errorf("failed to json unmarshal reponse body: %w", err)
	}

	fileIdBson, err := bson.ObjectIDFromHex(body.FileId)
	if err != nil {
		return dbmodels.Attachment{}, fmt.Errorf("failed to unmarshal bson object id for file id: %w", err)
	}

	return dbmodels.Attachment{
		FileId:          fileIdBson,
		Filename:        filename,
		ContentType:     http.DetectContentType(fileBytes),
		Size:            int64(len(fileBytes)),
		FileHash:        utils.ComputeSHA256(fileBytes),
		AttachmentNonce: encAttach.Nonce,
	}, nil
}

func clearErrorAfter(t time.Duration) tea.Cmd {
	return tea.Tick(t, func(t time.Time) tea.Msg {
		return clearErrMessage{}
	})
}
