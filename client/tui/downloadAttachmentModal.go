package tui

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/iim-protocol/iimp/client/e2e"
	"github.com/iim-protocol/iimp/client/utils"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
)

// Bubbletea messages
type closeDownloadModalMsg struct{}
type tickPrgMsg struct{}

var prgDuration = 500 * time.Millisecond

type downloadAttachmentModalModel struct {
	// The message that the user had selected to download the attachment from
	message       dbmodels.Message
	viewport      viewport.Model
	progressbar   progress.Model
	isDownloading bool
	// base url to pass while creating the download link for the attachment.
	baseUrl            string
	width              int
	height             int
	selectedAttachment int
	progress           float64 // percentage of download completed
	err                error
	ctx                context.Context
}

func newDownloadAttachmentModalModel(ctx context.Context, message dbmodels.Message, baseUrl string) downloadAttachmentModalModel {
	vp := viewport.New(viewport.WithWidth(50), viewport.WithHeight(10))
	progressBar := progress.New(progress.WithDefaultBlend())
	progressBar.SetWidth(50)
	progressBar.ShowPercentage = true

	m := downloadAttachmentModalModel{
		ctx:         ctx,
		message:     message,
		viewport:    vp,
		progressbar: progressBar,
		baseUrl:     baseUrl,
	}

	m.viewport.SetContent(m.renderAttachments())
	m.viewport.GotoBottom()
	return m
}

func (m *downloadAttachmentModalModel) SetWidth(width int) *downloadAttachmentModalModel {
	m.width = width
	m.viewport.SetWidth(width - 4)
	return m
}

func (m *downloadAttachmentModalModel) SetHeight(height int) *downloadAttachmentModalModel {
	m.height = height
	m.viewport.SetHeight(height - 4)
	return m
}

func (m *downloadAttachmentModalModel) Init() tea.Cmd {
	return tea.Batch(m.progressbar.Init(), m.viewport.Init())
}

func (m *downloadAttachmentModalModel) Update(msg tea.Msg) (*downloadAttachmentModalModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := 2
		progressBarHeight := 2
		errorBarHeight := 2
		excessHeight := 2 // padding and borders

		usedHeight := headerHeight + progressBarHeight + errorBarHeight + excessHeight

		viewportHeight := m.height - usedHeight
		m.viewport.SetWidth(m.width - 2)
		m.viewport.SetHeight(viewportHeight)
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			var cmd tea.Cmd
			m, cmd = m.downloadSelectedAttachment()
			m.isDownloading = true
			return m, cmd
		case "up":
			if m.selectedAttachment > 0 {
				m.selectedAttachment--
				m.viewport.SetContent(m.renderAttachments())
			}
			return m, nil
		case "down":
			if m.selectedAttachment < len(m.message.Attachments)-1 {
				m.selectedAttachment++
				m.viewport.SetContent(m.renderAttachments())
			}
			return m, nil
		case "esc", "ctrl+c":
			return m, m.close()
		}
	case errMsg:
		m.err = msg.err
		return m, clearErrorAfter(5 * time.Second)
	case clearErrMessage:
		m.err = nil
		return m, nil
	case tickPrgMsg:
		if m.progress >= 1.0 {
			m.isDownloading = false
			break
		}
		return m, tea.Batch(
			tickCmd(prgDuration, m.checkProgressTeaCmd),
			m.progressbar.SetPercent(float64(m.progress)),
		)
	case progress.FrameMsg:
		var cmd tea.Cmd
		m.progressbar, cmd = m.progressbar.Update(msg)
		return m, cmd
	}

	var vpCmd, pCmd tea.Cmd
	m.viewport, vpCmd = m.viewport.Update(msg)
	m.progressbar, pCmd = m.progressbar.Update(msg)
	return m, tea.Batch(vpCmd, pCmd)
}

func (m *downloadAttachmentModalModel) View() tea.View {
	var sb strings.Builder

	header := "Select an attachment to download (Use arrow keys to navigate, [enter] to select, [ctrl+c] to cancel):"
	sb.WriteString(headerStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	if m.progress >= 1.0 {
		successMsg := headerStyle.Width(m.width).Render("Attachment downloaded successfully!")
		sb.WriteString(successMsg)
		sb.WriteString("\n")
	}

	// add viewport content
	sb.WriteString(m.viewport.View())
	sb.WriteString("\n")

	sb.WriteString(m.progressbar.View())
	sb.WriteString("\n")

	if m.err != nil {
		errorMsg := errorStyle.Width(m.width).Render(fmt.Sprintf("Error: %v", m.err))
		sb.WriteString(errorMsg)
		sb.WriteString("\n")
	}

	return tea.View{
		Content:     modalStyle.Render(sb.String()),
		WindowTitle: "Download Attachment",
	}
}

func (m *downloadAttachmentModalModel) renderAttachments() string {
	var sb strings.Builder
	if len(m.message.Attachments) == 0 {
		sb.WriteString("No attachments found in this message.")
		return sb.String()
	}
	for i, attachment := range m.message.Attachments {
		if i == m.selectedAttachment {
			fmt.Fprintf(&sb, "> %s\n", ownStyle.Render(attachment.Filename))
		} else {
			fmt.Fprintf(&sb, "  %s\n", timestampStyle.Render(attachment.Filename))

		}
		sb.WriteString(attachStyle.Render(fmt.Sprintf("   Size: %s 		Type: %s", utils.FormatSize(int64(attachment.Size)), attachment.ContentType)))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m *downloadAttachmentModalModel) downloadSelectedAttachment() (*downloadAttachmentModalModel, tea.Cmd) {
	m.progress = 0.0
	return m, tea.Sequence(
		tickCmd(prgDuration, m.checkProgressTeaCmd),
		func() tea.Msg {
			if len(m.message.Attachments) == 0 {
				return errMsg{err: fmt.Errorf("no attachments to download")}
			}
			convId := m.message.ConversationId.Hex()
			msgId := m.message.Id.Hex()
			attachment := m.message.Attachments[m.selectedAttachment]
			fileId := attachment.FileId.Hex()
			msgContentIdx := slices.IndexFunc(m.message.Contents, func(c dbmodels.MessageContentItem) bool {
				return c.Version == 1
			})
			msgContent := m.message.Contents[msgContentIdx]
			keyIdIdx := slices.IndexFunc(msgContent.MessageContent.EncryptionData, func(ed dbmodels.MessageEncryptionData) bool {
				return ed.RecipientId == dbmodels.IIMPSession.UserId
			})
			ed := msgContent.MessageContent.EncryptionData[keyIdIdx]
			privateKey, err := dbmodels.LocalUserKeyPairs[ed.Encryption.KeyId].GetPrivateKey()
			if err != nil {
				return errMsg{err: fmt.Errorf("failed to get private key for decryption: %w", err)}
			}
			urlPathname := iimp_go_client.DownloadAttachmentRequestRoutePath
			urlPathname = strings.ReplaceAll(urlPathname, "{conversationId}", convId)
			urlPathname = strings.ReplaceAll(urlPathname, "{messageId}", msgId)
			urlPathname = strings.ReplaceAll(urlPathname, "{fileId}", fileId)
			downloadUrl := fmt.Sprintf("%s%s", m.baseUrl, urlPathname)

			r, err := http.NewRequestWithContext(m.ctx, iimp_go_client.DownloadAttachmentRequestHTTPMethod, downloadUrl, nil)
			if err != nil {
				return errMsg{err: fmt.Errorf("failed to create download request: %w", err)}
			}
			r.Header.Set("Authorization", "Bearer "+dbmodels.IIMPSession.AccessToken)
			response, err := http.DefaultClient.Do(r)
			if err != nil {
				return errMsg{err: fmt.Errorf("failed to execute download request: %w", err)}
			}
			if response.StatusCode != http.StatusOK {
				return errMsg{err: fmt.Errorf("download request failed with status: %s", response.Status)}
			}

			tempFilePath, err := m.downloadBytes(response.Body, response.ContentLength)
			m.progress = .90
			encBytes, err := os.ReadFile(tempFilePath)
			if err != nil {
				return errMsg{err: fmt.Errorf("failed to read downloaded temporary file: %w", err)}
			}
			fileBytes, err := e2e.DecryptAttachment(encBytes, attachment.AttachmentNonce, utils.MapEncryptionData(msgContent.MessageContent.EncryptionData), dbmodels.IIMPSession.UserId, privateKey)
			if err != nil {
				return errMsg{err: fmt.Errorf("failed to decrypt attachment: %w", err)}
			}
			m.progress = 0.95

			messagesDir, err := dbmodels.GetMessagesDirectory(convId)
			if err != nil {
				return errMsg{err: fmt.Errorf("failed to get messages directory: %w", err)}
			}
			fileDirPath := filepath.Join(messagesDir, msgId, dbmodels.IIMPAttachmentsDirSuffix)
			if err := os.MkdirAll(fileDirPath, os.ModePerm); err != nil {
				return errMsg{err: fmt.Errorf("failed to create messages directory: %w", err)}
			}

			err = os.WriteFile(filepath.Join(fileDirPath, attachment.Filename), fileBytes, os.ModePerm)
			if err != nil {
				return errMsg{err: fmt.Errorf("failed to save downloaded attachment: %w", err)}
			}
			m.progress = 1.0
			return nil
		},
	)
}

func (m *downloadAttachmentModalModel) downloadBytes(responseBody io.Reader, total int64) (filepath string, err error) {
	buf := make([]byte, 32*1024) // 32 KB
	var downloaded int64
	var file *os.File
	file, err = os.CreateTemp("", "temp_encoded_bytes_iimp_client_*")
	if err != nil {
		return "", fmt.Errorf("failed to open temporary download file: %w", err)
	}
	for {
		n, readErr := responseBody.Read(buf)
		if n > 0 {
			downloaded += int64(n)
			m.progress = float64(downloaded) / float64(total)
			n, err = file.Write(buf[:n])
			if err != nil {
				return "", fmt.Errorf("failure to write temporary download file: %w", err)
			}
		}
		if readErr == io.EOF {
			err = file.Close()
			if err != nil {
				return "", fmt.Errorf("failed to close the temporary download file: %w", err)
			}
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("failed to read bytes from response body: %w", err)
		}
	}
	return file.Name(), nil
}

func (m *downloadAttachmentModalModel) close() tea.Cmd {
	return func() tea.Msg {
		return closeDownloadModalMsg{}
	}
}

func (m *downloadAttachmentModalModel) checkProgressTeaCmd() tea.Msg {
	return tickPrgMsg{}
}

func tickCmd(duration time.Duration, cmd tea.Cmd) tea.Cmd {
	return tea.Tick(duration, func(t time.Time) tea.Msg {
		return cmd()
	})
}
