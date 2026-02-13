package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

//go:embed templates/* static/*
var content embed.FS

type User struct {
	Username string
	PrivKey  [32]byte
	PubKey   [32]byte
}

type Message struct {
	Sender      string
	Target      string
	Content     string
	Timestamp   time.Time
	IsEncrypted bool
}

var (
	users       = make(map[string]*User)
	sessions    = make(map[string]string)
	chatHistory []Message
	mu          sync.Mutex
)

func encrypt(key []byte, text string) string {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(text), nil))
}

func decrypt(key []byte, hexText string) string {
	data, err := hex.DecodeString(hexText)
	if err != nil {
		return "[Error Decrypting]"
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "[Invalid Ciphertext]"
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "[Decryption Failed]"
	}
	return string(plaintext)
}

func main() {
	tmpl := template.Must(template.ParseFS(content, "templates/index.html"))

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			mu.Lock()
			cutoff := time.Now().Add(-12 * time.Hour)
			var updated []Message
			for _, m := range chatHistory {
				if m.Timestamp.After(cutoff) {
					updated = append(updated, m)
				}
			}
			chatHistory = updated
			mu.Unlock()
		}
	}()

	http.Handle("/static/", http.FileServer(http.FS(content)))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		var currentUser string
		if cookie, err := r.Cookie("session_id"); err == nil {
			currentUser = sessions[cookie.Value]
		}

		processedMessages := make([]Message, len(chatHistory))
		copy(processedMessages, chatHistory)

		if user, ok := users[currentUser]; ok {
			for i, m := range processedMessages {
				if m.IsEncrypted && m.Target == user.Username {
					sender, exist := users[m.Sender]
					if exist {
						shared, _ := curve25519.X25519(user.PrivKey[:], sender.PubKey[:])
						processedMessages[i].Content = decrypt(shared, m.Content)
					}
				}
			}
		}

		tmpl.Execute(w, map[string]interface{}{
			"Messages": processedMessages,
			"Username": currentUser,
		})
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.FormValue("username"))
		if name != "" {
			var priv [32]byte
			rand.Read(priv[:])
			pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)

			var pubArr [32]byte
			copy(pubArr[:], pub)

			mu.Lock()
			users[name] = &User{Username: name, PrivKey: priv, PubKey: pubArr}
			sid := fmt.Sprintf("%x", priv[:16])
			sessions[sid] = name
			mu.Unlock()

			http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, Path: "/", HttpOnly: true})
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		mu.Lock()
		senderName := sessions[cookie.Value]
		sender, userExists := users[senderName]
		mu.Unlock()

		if !userExists {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		text := r.FormValue("text")
		if text == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		msg := Message{Sender: senderName, Content: text, Timestamp: time.Now(), Target: "all"}

		if strings.HasPrefix(text, "@") {
			parts := strings.SplitN(text, " ", 2)
			targetName := strings.TrimPrefix(parts[0], "@")

			mu.Lock()
			target, targetExists := users[targetName]
			mu.Unlock()

			if targetExists && len(parts) > 1 {
				shared, _ := curve25519.X25519(sender.PrivKey[:], target.PubKey[:])
				msg.Content = encrypt(shared, parts[1])
				msg.Target = targetName
				msg.IsEncrypted = true
			}
		}

		mu.Lock()
		chatHistory = append(chatHistory, msg)
		mu.Unlock()
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("session_id"); err == nil {
			mu.Lock()
			username := sessions[cookie.Value]
			delete(sessions, cookie.Value)
			delete(users, username)
			mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	fmt.Println("Vincere Server running on http://127.0.0.1:8080")
	http.ListenAndServe(":8080", nil)
}
