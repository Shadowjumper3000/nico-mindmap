package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

//go:embed index.html
var static embed.FS

//go:embed seed.json
var seedJSON []byte

var (
	db        *sql.DB
	jwtKey    []byte
	upgrader  = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	hub       = &Hub{clients: make(map[*Client]bool), broadcast: make(chan []byte, 256), register: make(chan *Client), unregister: make(chan *Client)}
)

type Client struct {
	conn *websocket.Conn
	send chan []byte
	id   string
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
}

func (h *Hub) run() {
	for {
		select {
		case c := <-h.register:
			h.clients[c] = true
		case c := <-h.unregister:
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}
		case msg := <-h.broadcast:
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					close(c.send)
					delete(h.clients, c)
				}
			}
		}
	}
}

func genID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type State struct {
	Nodes []Node `json:"nodes"`
	Links []Link `json:"links"`
}

type Node struct {
	ID      string   `json:"id"`
	Label   string   `json:"label"`
	Group   string   `json:"group"`
	Comment string   `json:"comment"`
	Color   *string  `json:"color"`
	Border  bool     `json:"border"`
	Nico    bool     `json:"nico"`
	Lea     bool     `json:"lea"`
	X       *float64 `json:"x,omitempty"`
	Y       *float64 `json:"y,omitempty"`
}

type Link struct {
	Source  string `json:"source"`
	Target  string `json:"target"`
	Kind    string `json:"kind"`
	Comment string `json:"comment"`
}

func main() {
	var err error
	db, err = sql.Open("sqlite", "./data.db?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDB()
	seedDB()
	initUser()
	initJWT()

	go hub.run()

	http.HandleFunc("GET /api/state", authMiddleware(handleGetState))
	http.HandleFunc("PUT /api/state", authMiddleware(handlePutState))
	http.HandleFunc("POST /api/login", handleLogin)
	http.HandleFunc("GET /ws", handleWS)
	http.HandleFunc("GET /", handleStatic)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func initDB() {
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS state (
		id INTEGER PRIMARY KEY DEFAULT 1,
		data TEXT NOT NULL
	)`)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		hash TEXT NOT NULL
	)`)
}

func seedDB() {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM state").Scan(&count)
	if count > 0 {
		return
	}
	var s State
	if err := json.Unmarshal(seedJSON, &s); err != nil {
		log.Printf("seed error: %v", err)
		return
	}
	raw, _ := json.Marshal(s)
	_, err := db.Exec("INSERT INTO state (id, data) VALUES (1, ?)", string(raw))
	if err != nil {
		log.Printf("seed insert error: %v", err)
	}
}

func initUser() {
	pw := os.Getenv("AUTH_PASSWORD")
	if pw == "" {
		buf := make([]byte, 16)
		rand.Read(buf)
		pw = hex.EncodeToString(buf)
		log.Printf("AUTH_PASSWORD not set, generated: %s", pw)
	}
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		_, err = db.Exec("INSERT INTO users (username, hash) VALUES (?, ?)", "admin", string(hash))
		if err != nil {
			log.Fatalf("insert user: %v", err)
		}
	}
}

func initJWT() {
	key := os.Getenv("JWT_SECRET")
	if key == "" {
		buf := make([]byte, 32)
		rand.Read(buf)
		key = hex.EncodeToString(buf)
	}
	jwtKey = []byte(key)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("login decode error: %v", err)
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	var hash string
	err := db.QueryRow("SELECT hash FROM users WHERE username = 'admin'").Scan(&hash)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	claims := jwt.MapClaims{
		"sub": "admin",
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func handleGetState(w http.ResponseWriter, r *http.Request) {
	var raw string
	err := db.QueryRow("SELECT data FROM state WHERE id = 1").Scan(&raw)
	if err != nil {
		json.NewEncoder(w).Encode(State{Nodes: []Node{}, Links: []Link{}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(raw))
}

func handlePutState(w http.ResponseWriter, r *http.Request) {
	var s State
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(s)
	_, err := db.Exec(`INSERT INTO state (id, data) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET data = excluded.data`, string(raw))
	if err != nil {
		http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, _ := static.ReadFile("index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &Client{conn: conn, send: make(chan []byte, 256), id: genID()}
	hub.register <- c
	go c.writePump()
	go c.readPump()
}

func (c *Client) writePump() {
	defer c.conn.Close()
	for msg := range c.send {
		c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			break
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
		var data map[string]interface{}
		if json.Unmarshal(msg, &data) != nil {
			continue
		}
		data["id"] = c.id
		raw, _ := json.Marshal(data)
		if raw != nil {
			hub.broadcast <- raw
		}
	}
}
