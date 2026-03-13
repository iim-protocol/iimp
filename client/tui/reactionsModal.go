package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
)

type reactionsModalModel struct {
	message       dbmodels.Message
	viewport      viewport.Model
	textinput     textinput.Model
	width         int
	height        int
	selectedIndex int
	baseUrl       string
	err           error
	ctx           context.Context
}

type closeReactionsModalMsg struct{}

func newReactionsModalModel(ctx context.Context, message dbmodels.Message, baseUrl string) *reactionsModalModel {
	ti := textinput.New()
	ti.Placeholder = "Enter your reaction (emoji only)"
	ti.Focus()
	ti.CharLimit = 10
	ti.SetWidth(20)
	ti.SetValue(getReactionEmojiIfAny(message, dbmodels.IIMPSession.UserId))

	vp := viewport.New(viewport.WithWidth(50), viewport.WithHeight(10))
	m := &reactionsModalModel{
		textinput:     ti,
		viewport:      vp,
		message:       message,
		ctx:           ctx,
		baseUrl:       baseUrl,
		selectedIndex: -1,
	}

	m.viewport.SetContent(m.renderReactions())
	m.viewport.GotoBottom()
	return m
}

func (m *reactionsModalModel) Init() tea.Cmd {
	return m.viewport.Init()
}

func (m *reactionsModalModel) Update(msg tea.Msg) (*reactionsModalModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := 2
		errorBarHeight := 2
		excessHeight := 2
		usedHeight := headerHeight + errorBarHeight + excessHeight

		viewportHeight := m.height - usedHeight
		m.viewport.SetWidth(m.width - 2)
		m.viewport.SetHeight(viewportHeight)
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if m.selectedIndex == -1 {
				emoji := strings.TrimSpace(m.textinput.Value())
				if emoji != "" {
					return m.reactToMessage(&emoji)
				} else {
					return m.reactToMessage(nil)
				}
			}
		case "up":
			if m.selectedIndex == -1 {
				m.textinput.Blur()
				m.selectedIndex = len(m.message.UserSpecificData) - 1
			} else if m.selectedIndex > 0 {
				m.selectedIndex--
			}
			m.viewport.SetContent(m.renderReactions())
		case "down":
			if m.selectedIndex != -1 {
				if m.selectedIndex < len(m.message.UserSpecificData)-1 {
					m.selectedIndex++
				} else {
					m.textinput.Focus()
					m.selectedIndex = -1
				}
			}
			m.viewport.SetContent(m.renderReactions())
		case "esc", "ctrl+c":
			return m, m.close()
		}
	case errMsg:
		m.err = msg.err
		return m, nil
	case clearErrMessage:
		m.err = nil
		return m, nil
	}

	var cmds []tea.Cmd
	var vCmd tea.Cmd
	m.viewport, vCmd = m.viewport.Update(msg)
	cmds = append(cmds, vCmd)

	if m.selectedIndex == -1 {
		var tiCmd tea.Cmd
		m.textinput, tiCmd = m.textinput.Update(msg)
		cmds = append(cmds, tiCmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *reactionsModalModel) View() tea.View {
	var sb strings.Builder

	header := "Reactions: [ctrl+c to close] [arrow keys to navigate]"
	sb.WriteString(headerStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	if m.err != nil {
		sb.WriteString(errorStyle.Render(m.err.Error()))
		sb.WriteString("\n")
	}

	// add viewport content
	sb.WriteString(m.viewport.View())
	sb.WriteString("\n")

	sb.WriteString(m.textinput.View())

	return tea.View{
		Content:     modalStyle.Render(sb.String()),
		WindowTitle: "Reactions",
	}
}

func (m *reactionsModalModel) SetWidth(width int) *reactionsModalModel {
	m.width = width
	m.viewport.SetWidth(width - 4)
	return m
}

func (m *reactionsModalModel) SetHeight(height int) *reactionsModalModel {
	m.height = height
	m.viewport.SetHeight(height - 4)
	return m
}

func (m *reactionsModalModel) close() tea.Cmd {
	return func() tea.Msg {
		return closeReactionsModalMsg{}
	}
}

func (m *reactionsModalModel) renderReactions() string {
	var sb strings.Builder
	for i, usd := range m.message.UserSpecificData {
		style := timestampStyle
		if m.selectedIndex == i {
			style = ownStyle
		}
		if usd.Reaction != nil {
			sb.WriteString(
				style.Render(
					fmt.Sprintf("%s - %s (%s)", *usd.Reaction, usd.RecipientId, usd.ReactedAt.Time().Format(time.DateTime)),
				),
			)
		} else {
			sb.WriteString(
				style.Render(
					fmt.Sprintf("No reaction - %s", usd.RecipientId),
				),
			)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m *reactionsModalModel) reactToMessage(emoji *string) (*reactionsModalModel, tea.Cmd) {
	return m, func() tea.Msg {
		client := iimp_go_client.NewIIMP(m.baseUrl)
		authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
		res, err := client.ReactToMessage(m.ctx, iimp_go_client.ReactToMessageRequest{
			ConversationId: m.message.ConversationId.Hex(),
			MessageId:      m.message.Id.Hex(),
			Auth: iimp_go_client.ReactToMessageRequestAuthParams{
				Authorization: &authorization,
			},
			Body: iimp_go_client.ReactToMessageRequestBody{
				Reaction: emoji,
			},
		})
		if err != nil {
			return errMsg{err: fmt.Errorf("failed to react to message: %w", err)}
		}
		if res.StatusCode != 200 {
			return errMsg{err: fmt.Errorf("failed to react to message: status code %d", res.StatusCode)}
		}
		return nil
	}
}

func getReactionEmojiIfAny(message dbmodels.Message, userId string) string {
	for _, usd := range message.UserSpecificData {
		if usd.RecipientId == userId {
			if usd.Reaction != nil {
				return *usd.Reaction
			}
		}
	}
	return ""
}
