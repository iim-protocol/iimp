package dbmodels

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// These following models are only used for TUI client, not for server
type IIMPSessionFile struct {
	ServerUrl   string `json:"server_url"`
	UserId      string `json:"user_id"`
	AccessToken string `json:"access_token"`
	// RFC3339 format
	AccessTokenExpiry string `json:"access_token_expiry"`
	RefreshToken      string `json:"refresh_token"`
	// RFC3339 format
	SessionExpiry string `json:"session_expiry"`
}

var IIMPSession *IIMPSessionFile

var iimpDirSuffix = "iimp"

func LoadIIMPSession() (sessionExist bool, err error) {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return false, fmt.Errorf("failed to get user config directory: %w", err)
	}
	iimpDir := filepath.Join(userConfigDir, iimpDirSuffix)
	err = os.MkdirAll(iimpDir, os.ModePerm)
	if err != nil {
		return false, fmt.Errorf("failed to create iimp config directory: %w", err)
	}
	sessionFilePath := filepath.Join(iimpDir, "session.json")
	if _, err := os.Stat(sessionFilePath); os.IsNotExist(err) {
		// Session file does not exist, return an error
		return false, nil
	}
	sessionBytes, err := os.ReadFile(sessionFilePath)
	if err != nil {
		return false, fmt.Errorf("failed to read session file: %w", err)
	}
	IIMPSession = &IIMPSessionFile{}
	err = json.Unmarshal(sessionBytes, IIMPSession)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal session file: %w", err)
	}
	return true, nil
}

func ClearSessionFile() error {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get user config directory: %w", err)
	}
	sessionFilePath := filepath.Join(userConfigDir, iimpDirSuffix, "session.json")
	if _, err := os.Stat(sessionFilePath); os.IsNotExist(err) {
		// Session file does not exist, nothing to clear
		return nil
	}
	return os.Remove(sessionFilePath)
}

func SaveIIMPSession(session *IIMPSessionFile) error {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get user config directory: %w", err)
	}
	sessionFilePath := filepath.Join(userConfigDir, iimpDirSuffix, "session.json")
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session file: %w", err)
	}
	return os.WriteFile(sessionFilePath, sessionBytes, 0600)
}
