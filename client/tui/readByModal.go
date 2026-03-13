package tui

import (
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
)

type closeReadByModalMsg struct{}

type readByModalModel struct {
	message      dbmodels.Message
	viewport     viewport.Model
	width        int
	height       int
	selectedItem int
}

func newReadByModalModel(message dbmodels.Message) *readByModalModel {
	vp := viewport.New(viewport.WithWidth(50), viewport.WithHeight(10))
	m := readByModalModel{
		message:  message,
		viewport: vp,
	}

	m.viewport.SetContent(m.renderReadBy())
	m.viewport.GotoBottom()
	return &m
}

func (m *readByModalModel) SetWidth(width int) *readByModalModel {
	m.width = width
	m.viewport.SetWidth(width)
	return m
}

func (m *readByModalModel) SetHeight(height int) *readByModalModel {
	m.height = height
	m.viewport.SetHeight(height - 4)
	return m
}

func (m *readByModalModel) Init() tea.Cmd {
	return m.viewport.Init()
}

func (m *readByModalModel) Update(msg tea.Msg) (*readByModalModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "enter", "ctrl+c":
			return m, m.close()
		case "up":
			if m.selectedItem > 0 {
				m.selectedItem--
				m.viewport.SetContent(m.renderReadBy())
			}
		case "down":
			if m.selectedItem < len(m.message.UserSpecificData)-1 {
				m.selectedItem++
				m.viewport.SetContent(m.renderReadBy())
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

func (m *readByModalModel) View() tea.View {
	var sb strings.Builder
	header := "Message - Read By (Use arrow keys to navigate, [ctrl+c] to go back):"
	sb.WriteString(headerStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	sb.WriteString(m.viewport.View())
	sb.WriteString("\n")

	return tea.View{
		Content:     modalStyle.Render(sb.String()),
		WindowTitle: "Message - Read By",
	}
}

func (m *readByModalModel) renderReadBy() string {
	var sb strings.Builder
	for i, usd := range m.message.UserSpecificData {
		prefix := "  "
		style := timestampStyle
		if i == m.selectedItem {
			prefix = "> "
			style = ownStyle
		}
		line := prefix + usd.RecipientId
		if usd.ReadAt != nil {
			line += "\n(Read, " + usd.ReadAt.Time().Format(time.DateTime) + ")"
		} else {
			line += " (Unread)"
		}
		sb.WriteString(style.Width(m.viewport.Width()).Align(lipgloss.Center).Render(line))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m *readByModalModel) close() tea.Cmd {
	return func() tea.Msg {
		return closeReadByModalMsg{}
	}
}
