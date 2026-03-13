package dbmodels

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
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
var iimpSessionFileName = "session.json"
var iimpConversationsDirSuffix = "conversations"
var iimpMessagesDirSuffix = "messages"
var iimpCursorFileName = "cursor.json"
var IIMPAttachmentsDirSuffix = "attachments"

func getConversationsDirectory() (string, error) {
	sessionDir, err := getSessionSpecificDir()
	if err != nil {
		return "", fmt.Errorf("failed to get session specific directory: %w", err)
	}
	conversationsDir := filepath.Join(sessionDir, iimpConversationsDirSuffix)
	err = os.MkdirAll(conversationsDir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to create iimp conversations directory: %w", err)
	}
	return conversationsDir, nil
}

func GetMessagesDirectory(conversationId string) (string, error) {
	sessionDir, err := getSessionSpecificDir()
	if err != nil {
		return "", fmt.Errorf("failed to get session specific directory: %w", err)
	}
	messagesDir := filepath.Join(sessionDir, conversationId, iimpMessagesDirSuffix)
	err = os.MkdirAll(messagesDir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to create iimp conversation messages directory: %w", err)
	}
	return messagesDir, nil
}

type SessionCursor struct {
	Cursor string
}

func getCursorFilePath() (string, error) {
	sessionDir, err := getSessionSpecificDir()
	if err != nil {
		return "", fmt.Errorf("failed to get session specific directory: %w", err)
	}
	cursorFilePath := filepath.Join(sessionDir, iimpCursorFileName)
	if _, err = os.Stat(cursorFilePath); os.IsNotExist(err) {
		// Cursor file does not exist, create an empty one
		emptyCursor := &SessionCursor{Cursor: ""}
		cursorBytes, err := json.Marshal(emptyCursor)
		if err != nil {
			return "", fmt.Errorf("failed to marshal empty cursor: %w", err)
		}
		err = os.WriteFile(cursorFilePath, cursorBytes, 0600)
		if err != nil {
			return "", fmt.Errorf("failed to create cursor file: %w", err)
		}
	}
	return cursorFilePath, nil
}

func getSessionSpecificDir() (string, error) {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	suffix := base64.RawStdEncoding.EncodeToString([]byte(IIMPSession.ServerUrl + "_" + IIMPSession.UserId))
	sessionDir := filepath.Join(userConfigDir, iimpDirSuffix, suffix)
	err = os.MkdirAll(sessionDir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to create session specific directory: %w", err)
	}
	return sessionDir, nil
}

// May return "" string for cursor and nil for error, which means
// no cursor exists. start afresh!
func GetCursor() (string, error) {
	cursorFilePath, err := getCursorFilePath()
	if err != nil {
		return "", fmt.Errorf("failed to get cursor file path: %w", err)
	}
	cursorBytes, err := os.ReadFile(cursorFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read cursor file: %w", err)
	}
	cursor := &SessionCursor{}
	err = json.Unmarshal(cursorBytes, cursor)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal cursor file: %w", err)
	}
	return cursor.Cursor, nil
}

func SaveCursor(cursor string) error {
	cursorFilePath, err := getCursorFilePath()
	if err != nil {
		return fmt.Errorf("failed to get cursor file path: %w", err)
	}
	cursorBytes, err := json.Marshal(&SessionCursor{Cursor: cursor})
	if err != nil {
		return fmt.Errorf("failed to marshal cursor: %w", err)
	}
	return os.WriteFile(cursorFilePath, cursorBytes, 0600)
}

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
	sessionFilePath := filepath.Join(iimpDir, iimpSessionFileName)
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
	sessionFilePath := filepath.Join(userConfigDir, iimpDirSuffix, iimpSessionFileName)
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
	sessionFilePath := filepath.Join(userConfigDir, iimpDirSuffix, iimpSessionFileName)
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session file: %w", err)
	}
	return os.WriteFile(sessionFilePath, sessionBytes, 0600)
}

type LocalKeyPairModel struct {
	// Base 64 RawURL encoded X25519 private key
	PrivateKeyEncoded string `json:"private_key_encoded"`

	// Base 64 RawURL encoded X25519 public key
	PublicKeyEncoded string `json:"public_key_encoded"`

	// User ID
	UserId string `json:"user_id"`

	// Key ID
	//
	// SHA256 hash of the public key, encoded in Base 64 RawURL format. This serves as a unique identifier for the key pair.
	KeyID string `json:"key_id"`

	// The IIMP Server URL that this key pair is associated with
	//
	// This keypair is used for message encryption for the given server URL.
	ServerUrl string `json:"server_url"`

	privateKey []byte `json:"-"`
	publicKey  []byte `json:"-"`
}

func (k *LocalKeyPairModel) GetPrivateKey() ([]byte, error) {
	if k.privateKey != nil {
		return k.privateKey, nil
	}
	if k.PrivateKeyEncoded == "" {
		return nil, fmt.Errorf("private key is empty")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(k.PrivateKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	k.privateKey = decoded
	return k.privateKey, nil
}

func (k *LocalKeyPairModel) GetPublicKey() ([]byte, error) {
	if k.publicKey != nil {
		return k.publicKey, nil
	}
	if k.PublicKeyEncoded == "" {
		return nil, fmt.Errorf("public key is empty")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(k.PublicKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	k.publicKey = decoded
	return k.publicKey, nil
}

func GenerateAndSaveKeys(userId, serverUrl string) (*LocalKeyPairModel, error) {
	// Generate X25519 key pair
	privateKey := make([]byte, curve25519.ScalarSize)
	_, err := rand.Read(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random private key: %w", err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	// Encode keys in Base64 RawURL format
	privateKeyEncoded := base64.RawURLEncoding.EncodeToString(privateKey)
	publicKeyEncoded := base64.RawURLEncoding.EncodeToString(publicKey)

	// Generate Key ID as SHA256 hash of the public key, encoded in Base64 RawURL format
	keyIDBytes := sha256.Sum256(publicKey)
	keyID := base64.RawURLEncoding.EncodeToString(keyIDBytes[:])

	// Create LocalKeyPairModel
	keyPairModel := &LocalKeyPairModel{
		PrivateKeyEncoded: privateKeyEncoded,
		PublicKeyEncoded:  publicKeyEncoded,
		UserId:            userId,
		KeyID:             keyID,
		ServerUrl:         serverUrl,
	}

	// save the keypair to a file named {userId}_{serverUrl}_{keyID}.json in the same directory as the session file
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user config directory: %w", err)
	}
	keyPairFileName := fmt.Sprintf("%s_%s_%s.json", userId, base64.RawURLEncoding.EncodeToString([]byte(serverUrl)), keyID)
	keyPairFilePath := filepath.Join(userConfigDir, iimpDirSuffix, keyPairFileName)
	keyPairBytes, err := json.Marshal(keyPairModel)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key pair model: %w", err)
	}

	err = os.WriteFile(keyPairFilePath, keyPairBytes, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write key pair file: %w", err)
	}

	return keyPairModel, nil
}

// In-memory cache to store loaded key pairs, keyed by the keyId
var LocalUserKeyPairs map[string]*LocalKeyPairModel = make(map[string]*LocalKeyPairModel)

func KeypairExistsForServerAndUser(userId, serverUrl string) (bool, error) {
	sessionExists, err := LoadIIMPSession()
	if err != nil {
		return false, fmt.Errorf("failed to load session: %w", err)
	}
	if !sessionExists {
		return false, fmt.Errorf("no active session found")
	}
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return false, fmt.Errorf("failed to get user config directory: %w", err)
	}
	keyPairFileName := fmt.Sprintf("%s_%s_*.json", userId, base64.RawURLEncoding.EncodeToString([]byte(serverUrl)))
	matches, err := filepath.Glob(filepath.Join(userConfigDir, iimpDirSuffix, keyPairFileName))
	if err != nil {
		return false, fmt.Errorf("failed to glob for key pair file: %w", err)
	}
	return len(matches) > 0, nil
}

func LoadKeys() error {
	// Load the key pair file for the current user and server
	sessionExists, err := LoadIIMPSession()
	if err != nil {
		return fmt.Errorf("failed to load session: %w", err)
	}
	if !sessionExists {
		return fmt.Errorf("no active session found")
	}
	userId := IIMPSession.UserId
	serverUrl := IIMPSession.ServerUrl

	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get user config directory: %w", err)
	}
	keyPairFileName := fmt.Sprintf("%s_%s_*.json", userId, base64.RawURLEncoding.EncodeToString([]byte(serverUrl)))
	matches, err := filepath.Glob(filepath.Join(userConfigDir, iimpDirSuffix, keyPairFileName))
	if err != nil {
		return fmt.Errorf("failed to glob for key pair file: %w", err)
	}
	if len(matches) == 0 {
		return fmt.Errorf("no key pair file found for user %s and server %s", userId, serverUrl)
	}
	for _, match := range matches {
		keyPairBytes, err := os.ReadFile(match)
		if err != nil {
			return fmt.Errorf("failed to read key pair file %s: %w", match, err)
		}
		keyPairModel := &LocalKeyPairModel{}
		err = json.Unmarshal(keyPairBytes, keyPairModel)
		if err != nil {
			return fmt.Errorf("failed to unmarshal key pair file %s: %w", match, err)
		}
		LocalUserKeyPairs[keyPairModel.KeyID] = keyPairModel
	}
	return nil
}

func SaveConversation(conversation *Conversation) error {
	// Save the conversation to a file named {conversationId}.json in the conversations directory for the server
	conversationsDir, err := getConversationsDirectory()
	if err != nil {
		return fmt.Errorf("failed to get conversations directory: %w", err)
	}
	conversationFilePath := filepath.Join(conversationsDir, fmt.Sprintf("%s.json", conversation.Id.Hex()))
	conversationBytes, err := json.Marshal(conversation)
	if err != nil {
		return fmt.Errorf("failed to marshal conversation: %w", err)
	}
	err = os.WriteFile(conversationFilePath, conversationBytes, 0600)
	if err != nil {
		return fmt.Errorf("failed to write conversation file: %w", err)
	}
	return nil
}

func ListConversations() ([]*Conversation, error) {
	// List all conversation files in the conversations directory for the server and return the conversations
	conversationsDir, err := getConversationsDirectory()
	if err != nil {
		return nil, fmt.Errorf("failed to get conversations directory: %w", err)
	}
	files, err := os.ReadDir(conversationsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read conversations directory: %w", err)
	}
	var conversations []*Conversation
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		conversationBytes, err := os.ReadFile(filepath.Join(conversationsDir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read conversation file %s: %w", file.Name(), err)
		}
		conversation := &Conversation{}
		err = json.Unmarshal(conversationBytes, conversation)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal conversation file %s: %w", file.Name(), err)
		}
		conversations = append(conversations, conversation)
	}
	return conversations, nil
}

func SaveMessage(message *Message) error {
	messagesDir, err := GetMessagesDirectory(message.ConversationId.Hex())
	if err != nil {
		return fmt.Errorf("failed to get messages directory: %w", err)
	}
	messageFilePath := filepath.Join(messagesDir, fmt.Sprintf("%s.json", message.Id.Hex()))
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}
	return os.WriteFile(messageFilePath, messageBytes, 0600)
}

func ListMessages(conversationId string) ([]Message, error) {
	messagesDir, err := GetMessagesDirectory(conversationId)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages directory: %w", err)
	}
	files, err := os.ReadDir(messagesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read messages directory: %w", err)
	}
	var messages []Message = make([]Message, 0)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		messageBytes, err := os.ReadFile(filepath.Join(messagesDir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read message file %s: %w", file.Name(), err)
		}
		message := Message{}
		if err = json.Unmarshal(messageBytes, &message); err != nil {
			return nil, fmt.Errorf("failed to unmarshal message file %s: %w", file.Name(), err)
		}
		messages = append(messages, message)
	}
	return messages, nil
}
