package main

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
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
	mu          sync.RWMutex
)

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

func encrypt(sharedSecret []byte, text string) string {
	res, err := encryptFull(sharedSecret, text)
	if err != nil {
		return "[Encryption Error]"
	}
	return res
}

func decrypt(sharedSecret []byte, hexText string) string {
	res, err := decryptFull(sharedSecret, hexText)
	if err != nil {
		return "[Integritätsfehler]"
	}
	return res
}

func main() {
	tmpl := template.Must(template.ParseFS(content, "templates/*.html"))

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
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
		onlineString := myJoin(onlineNames, ", ")

		var uname, ucol string
		if currentUser != nil {
			uname = currentUser.Username
			ucol = currentUser.Color
		}
		mu.RUnlock()

		tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
			"Username":    uname,
			"UserColor":   ucol,
			"OnlineUsers": onlineString,
		})
	})

	http.HandleFunc("/server-logs", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		logsCopy := make([]string, len(serverLogs))
		copy(logsCopy, serverLogs)
		mu.RUnlock()

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><meta http-equiv='refresh' content='2'><style>body{background:#000;color:#0f0;font-family:monospace;font-size:12px;margin:10px;overflow-x:hidden;} .crypto{color:#f0f;} .auth{color:#0af;} .msg{color:#ff0;}</style></head><body>")
		for _, l := range logsCopy {
			class := ""
			if myContains(l, "CRYPTO") {
				class = "class='crypto'"
			}
			if myContains(l, "AUTH") {
				class = "class='auth'"
			}
			if myContains(l, "MSG") {
				class = "class='msg'"
			}
			fmt.Fprintf(w, "<div %s>%s</div>", class, l)
		}
		fmt.Fprint(w, "</body></html>")
	})

	http.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		var currentUser *User
		if cookie, err := r.Cookie("session_id"); err == nil {
			if name, ok := sessions[cookie.Value]; ok {
				currentUser = users[name]
			}
		}

		rawHistory := make([]Message, len(chatHistory))
		copy(rawHistory, chatHistory)
		mu.RUnlock()

		reversed := make([]Message, len(rawHistory))
		for i := 0; i < len(rawHistory); i++ {
			reversed[i] = rawHistory[len(rawHistory)-1-i]
		}

		if currentUser != nil {
			for i, m := range reversed {
				if m.IsEncrypted && m.Target == currentUser.Username {
					mu.RLock()
					sender, exist := users[m.Sender]
					mu.RUnlock()
					if exist {
						shared, _ := X25519(currentUser.PrivKey, sender.PubKey)
						reversed[i].Sender = m.Sender
						reversed[i].Content = decrypt(shared[:], m.Content)
					}
				}
			}
		}

		tmpl.ExecuteTemplate(w, "messages.html", map[string]interface{}{
			"Messages": reversed,
			"Username": func() string {
				if currentUser != nil {
					return currentUser.Username
				}
				return ""
			}(),
		})
	})

	http.HandleFunc("/input", func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "input.html", nil)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		name := myTrimSpace(r.FormValue("username"))
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
			sid := myHexEncode(priv[:16])
			sessions[sid] = name
			mu.Unlock()

			addLog("AUTH", "Session created for "+name)
			http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/input", http.StatusSeeOther)
			return
		}
		mu.RLock()
		senderName := sessions[cookie.Value]
		sender, ok := users[senderName]
		mu.RUnlock()
		if !ok {
			http.Redirect(w, r, "/input", http.StatusSeeOther)
			return
		}

		text := myTrimSpace(r.FormValue("text"))
		if text != "" {
			msg := Message{Sender: senderName, Content: text, Timestamp: time.Now(), Target: "all", Color: sender.Color}

			if myHasPrefix(text, "@") {
				parts := mySplitN(text, " ", 2)
				targetName := myTrimPrefix(parts[0], "@")

				mu.RLock()
				target, exists := users[targetName]
				mu.RUnlock()

				if exists && len(parts) > 1 {
					addLog("CRYPTO", fmt.Sprintf("Initiating E2EE: %s -> %s", senderName, targetName))
					shared, _ := X25519(sender.PrivKey, target.PubKey)
					msg.Content = encrypt(shared[:], parts[1])
					msg.Target = targetName
					msg.IsEncrypted = true
					addLog("MSG", "IGE E2EE stored.")
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

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == nil {
			sid := cookie.Value

			mu.Lock()
			name, ok := sessions[sid]
			if ok {
				delete(users, name)
				delete(sessions, sid)
			}
			mu.Unlock()

			if ok {
				addLog("AUTH", "User logout: "+name)
			}
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	fmt.Println("vincere messenger running.")
	fmt.Println("Address: http://127.0.0.1:8080")
	addLog("SYSTEM", "Server started on :8080")
	http.ListenAndServe(":8080", nil)
}
