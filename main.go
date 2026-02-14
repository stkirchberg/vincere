package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed templates/* static/*
var content embed.FS

type User struct {
	Username string
	PrivKey  [32]byte
	PubKey   [32]byte
	Color    string
}

type Message struct {
	Sender      string
	Target      string
	Content     string
	Timestamp   time.Time
	IsEncrypted bool
	Color       string
}

var (
	users       = make(map[string]*User)
	sessions    = make(map[string]string)
	chatHistory []Message
	serverLogs  []string
	mu          sync.Mutex
)

// --- LOGGING HELPER ---

func addLog(category, message string) {
	mu.Lock()
	defer mu.Unlock()
	timestamp := time.Now().Format("15:04:05.000")
	entry := fmt.Sprintf("[%s] %-10s | %s", timestamp, category, message)
	serverLogs = append(serverLogs, entry)

	if len(serverLogs) > 200 {
		serverLogs = serverLogs[1:]
	}
}

// --- CRYPTO HELPERS ---

func encrypt(key []byte, text string) string {
	iv := make([]byte, 32)
	rand.Read(iv)
	padded := pad([]byte(text))
	ciphered, _ := aesIgeEncrypt(key, iv, padded)
	final := append(iv, ciphered...)
	return hex.EncodeToString(final)
}

func decrypt(key []byte, hexText string) string {
	data, err := hex.DecodeString(hexText)
	if err != nil || len(data) < 32 {
		return "[Error]"
	}
	iv := data[:32]
	ciphered := data[32:]
	plainPadded, err := aesIgeDecrypt(key, iv, ciphered)
	if err != nil {
		return "[Decryption Failed]"
	}
	return string(unpad(plainPadded))
}

func main() {
	tmpl := template.Must(template.ParseFS(content, "templates/*.html"))

	// Cleanup-Routine
	go func() {
		for {
			time.Sleep(1 * time.Minute)
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
			addLog("SYSTEM", "Routine cleanup: Old messages purged.")
		}
	}()

	http.Handle("/static/", http.FileServer(http.FS(content)))

	// INDEX
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		var currentUser *User
		if cookie, err := r.Cookie("session_id"); err == nil {
			if name, ok := sessions[cookie.Value]; ok {
				currentUser = users[name]
			}
		}

		var onlineNames []string
		for _, u := range users {
			onlineNames = append(onlineNames, u.Username)
		}
		onlineString := strings.Join(onlineNames, ", ")

		var uname, ucol string
		if currentUser != nil {
			uname = currentUser.Username
			ucol = currentUser.Color
		}
		mu.Unlock()

		tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
			"Username":    uname,
			"UserColor":   ucol,
			"OnlineUsers": onlineString,
		})
	})

	// SERVER LOGS ENDPUNKT
	http.HandleFunc("/server-logs", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		logsCopy := make([]string, len(serverLogs))
		copy(logsCopy, serverLogs)
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><meta http-equiv='refresh' content='2'><style>body{background:#000;color:#0f0;font-family:monospace;font-size:12px;margin:10px;overflow-x:hidden;} .crypto{color:#f0f;} .auth{color:#0af;} .msg{color:#ff0;}</style></head><body>")
		for _, l := range logsCopy {
			class := ""
			if strings.Contains(l, "CRYPTO") {
				class = "class='crypto'"
			}
			if strings.Contains(l, "AUTH") {
				class = "class='auth'"
			}
			if strings.Contains(l, "MSG") {
				class = "class='msg'"
			}
			fmt.Fprintf(w, "<div %s>%s</div>", class, l)
		}
		fmt.Fprint(w, "<script>window.scrollTo(0,document.body.scrollHeight);</script></body></html>")
	})

	// MESSAGES FRAME
	http.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		var currentUser *User
		if cookie, err := r.Cookie("session_id"); err == nil {
			if name, ok := sessions[cookie.Value]; ok {
				currentUser = users[name]
			}
		}

		processed := make([]Message, len(chatHistory))
		copy(processed, chatHistory)

		if currentUser != nil {
			for i, m := range processed {
				if m.IsEncrypted && m.Target == currentUser.Username {
					sender, exist := users[m.Sender]
					if exist {
						shared, _ := X25519(currentUser.PrivKey, sender.PubKey)
						processed[i].Content = decrypt(shared[:], m.Content)
					}
				}
			}
		}
		mu.Unlock()

		tmpl.ExecuteTemplate(w, "messages.html", map[string]interface{}{
			"Messages": processed,
			"Username": func() string {
				if currentUser != nil {
					return currentUser.Username
				}
				return ""
			}(),
		})
	})

	// INPUT FRAME
	http.HandleFunc("/input", func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "input.html", nil)
	})

	// LOGIN
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.FormValue("username"))
		color := r.FormValue("color")
		if name != "" {
			addLog("AUTH", "Generating new X25519 keypair for user: "+name)
			priv, pub := GenerateKeyPair()

			mu.Lock()
			users[name] = &User{
				Username: name,
				PrivKey:  priv,
				PubKey:   pub,
				Color:    color,
			}
			sid := hex.EncodeToString(priv[:16])
			sessions[sid] = name
			mu.Unlock()

			addLog("AUTH", "Session created for "+name)
			http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, Path: "/", HttpOnly: true})
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// SEND
	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/input", http.StatusSeeOther)
			return
		}
		mu.Lock()
		senderName := sessions[cookie.Value]
		sender, ok := users[senderName]
		mu.Unlock()
		if !ok {
			http.Redirect(w, r, "/input", http.StatusSeeOther)
			return
		}

		text := strings.TrimSpace(r.FormValue("text"))
		if text != "" {
			msg := Message{Sender: senderName, Content: text, Timestamp: time.Now(), Target: "all", Color: sender.Color}

			if strings.HasPrefix(text, "@") {
				parts := strings.SplitN(text, " ", 2)
				targetName := strings.TrimPrefix(parts[0], "@")

				mu.Lock()
				target, exists := users[targetName]
				mu.Unlock()

				if exists && len(parts) > 1 {
					addLog("CRYPTO", fmt.Sprintf("Initiating E2EE: %s -> %s", senderName, targetName))
					shared, _ := X25519(sender.PrivKey, target.PubKey)
					msg.Content = encrypt(shared[:], parts[1])
					msg.Target = targetName
					msg.IsEncrypted = true
					addLog("MSG", "Encrypted private message stored.")
				} else {
					addLog("MSG", "Public message from "+senderName)
				}
			} else {
				addLog("MSG", "Public message from "+senderName)
			}

			mu.Lock()
			chatHistory = append(chatHistory, msg)
			mu.Unlock()
		}
		http.Redirect(w, r, "/input", http.StatusSeeOther)
	})

	// LOGOUT
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("session_id"); err == nil {
			mu.Lock()
			name := sessions[cookie.Value]
			addLog("AUTH", "User logout: "+name)
			delete(sessions, cookie.Value)
			delete(users, name)
			mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	fmt.Println("Vincere Messenger running.")
	fmt.Println("Address: http://127.0.0.1:8080")
	addLog("SYSTEM", "Server started on :8080")
	http.ListenAndServe(":8080", nil)
}
