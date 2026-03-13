package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/iim-protocol/iimp/client/utils"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
)

type closeMessageHistoryModalMsg struct{}

type messageHistoryModalModel struct {
	message      dbmodels.Message
	viewport     viewport.Model
	width        int
	height       int
	selectedItem int
}

func newMessageHistoryModalModel(message dbmodels.Message) *messageHistoryModalModel {
	vp := viewport.New(viewport.WithWidth(50), viewport.WithHeight(10))
	m := messageHistoryModalModel{
		message:  message,
		viewport: vp,
	}

	m.viewport.SetContent(m.renderMessageHistory())
	m.viewport.GotoBottom()
	return &m
}

func (m *messageHistoryModalModel) SetWidth(width int) *messageHistoryModalModel {
	m.width = width
	m.viewport.SetWidth(width)
	return m
}

func (m *messageHistoryModalModel) SetHeight(height int) *messageHistoryModalModel {
	m.height = height
	m.viewport.SetHeight(height - 4)
	return m
}

func (m *messageHistoryModalModel) Init() tea.Cmd {
	return m.viewport.Init()
}

func (m *messageHistoryModalModel) Update(msg tea.Msg) (*messageHistoryModalModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "enter", "ctrl+c":
			return m, m.close()
		case "up":
			if m.selectedItem > 0 {
				m.selectedItem--
				m.viewport.SetContent(m.renderMessageHistory())
			}
		case "down":
			if m.selectedItem < len(m.message.Contents)-1 {
				m.selectedItem++
				m.viewport.SetContent(m.renderMessageHistory())
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := 2
		excessHeight := 2
		usedHeight := headerHeight + excessHeight

		viewportHeight := m.height - usedHeight
		m.viewport.SetWidth(m.width)
		m.viewport.SetHeight(viewportHeight)
	}
	var vpCmd tea.Cmd
	m.viewport, vpCmd = m.viewport.Update(msg)
	return m, vpCmd
}

func (m *messageHistoryModalModel) View() tea.View {
	var sb strings.Builder

	header := fmt.Sprintf("Message History - %s (use arrow keys to navigate, ctrl+c to go back):", m.message.SenderUserId)
	sb.WriteString(headerStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	sb.WriteString(m.viewport.View())
	sb.WriteString("\n")

	return tea.View{
		Content:     modalStyle.Render(sb.String()),
		WindowTitle: "Message History - " + m.message.SenderUserId,
	}
}

func (m *messageHistoryModalModel) renderMessageHistory() string {
	var sb strings.Builder
	for idx, historyItem := range m.message.Contents {
		prefix := "  "
		if idx == m.selectedItem {
			prefix = "> "
		}
		content, timestamp := utils.GetMsgPlaintext(historyItem.MessageContent, dbmodels.IIMPSession.UserId)
		line := fmt.Sprintf("%sVersion %d - Sent At: %s", prefix, historyItem.Version, timestamp.Format(time.DateTime))
		sb.WriteString(ownStyle.Width(m.width).Render(line))
		sb.WriteString("\n")
		sb.WriteString(editedStyle.Width(m.width).Render(content))
	}
	return sb.String()
}

func (m *messageHistoryModalModel) close() tea.Cmd {
	return func() tea.Msg {
		return closeMessageHistoryModalMsg{}
	}
}
