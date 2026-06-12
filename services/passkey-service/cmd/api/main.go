package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"passkey-service/internal/db"
	wl "passkey-service/internal/webauthn"
)

var (
	database     *db.DB
	webAuthn     *webauthn.WebAuthn
	jwtSecretKey []byte
)

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func authMiddleware(requiredRoles []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"message":"Unauthorized: Missing token"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, `{"message":"Unauthorized: Invalid token"}`, http.StatusUnauthorized)
			return
		}

		if len(requiredRoles) > 0 {
			roleMatch := false
			for _, role := range requiredRoles {
				if claims.Role == role {
					roleMatch = true
					break
				}
			}
			if !roleMatch {
				http.Error(w, `{"message":"Forbidden: Insufficient privileges"}`, http.StatusForbidden)
				return
			}
		}

		next(w, r)
	}
}

func main() {
	log.Println("Starting Passkey Service...")

	jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if os.Getenv("JWT_SECRET_KEY") == "" {
		log.Fatal("FATAL: JWT_SECRET_KEY is not set")
	}

	// Connect to Database
	var err error
	database, err = db.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to Database: %v", err)
	}
	defer database.Close()

	// Initialize WebAuthn
	rpID := os.Getenv("RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}
	rpDisplayName := os.Getenv("RP_DISPLAY_NAME")
	if rpDisplayName == "" {
		rpDisplayName = "Inglis Horizon"
	}
	rpOriginsEnv := os.Getenv("RP_ORIGINS")
	var rpOrigins []string
	if rpOriginsEnv != "" {
		cleanedOrigins := strings.ReplaceAll(rpOriginsEnv, ",", " ")
		rpOrigins = strings.Fields(cleanedOrigins)
	} else {
		rpOrigins = []string{"http://localhost:8080", "http://localhost:8484"}
	}

	log.Printf("WebAuthn Configuration: RPID=%s, Origins=%v", rpID, rpOrigins)

	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			UserVerification:        protocol.VerificationRequired,
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize WebAuthn: %v", err)
	}

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// API Routes
	r.Post("/tokens", authMiddleware([]string{"MANAGER"}, createTokenHandler))
	r.Get("/tokens/{token}", getTargetAccountHandler)
	r.Get("/register/begin", startRegistrationHandler)
	r.Post("/register/finish", finishRegistrationHandler)
	r.Get("/auth/begin", startLoginHandler)
	r.Post("/auth/finish", finishLoginHandler)

	// Serve Static Files
	workDir, _ := os.Getwd()
	staticDir := workDir + "/web/static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		log.Printf("Static files directory %s not found. Static files won't be served.", staticDir)
	} else {
		log.Printf("Serving static files from: %s", staticDir)
		fileServer(r, "/link", http.Dir(staticDir))
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8484"
	}

	log.Printf("Passkey Service running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func fileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit any URL parameters.")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

// Handler: POST /tokens
func createTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID string `json:"account_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
		return
	}

	if req.AccountID == "" {
		http.Error(w, `{"message":"account_id is required"}`, http.StatusBadRequest)
		return
	}

	// Verify account exists in ledger database
	var accountExists bool
	err := database.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM financial_accounts WHERE id = $1 AND status != 'CLOSED')", req.AccountID).Scan(&accountExists)
	if err != nil || !accountExists {
		http.Error(w, `{"message":"Account not found or is closed"}`, http.StatusNotFound)
		return
	}

	// Generate UUID Token, default Challenge, default User ID
	token := uuidStr()
	challenge := "placeholder"
	userID := make([]byte, 32) // Will be populated dynamically in begin step

	expiresAt := time.Now().Add(15 * time.Minute)

	query := `
		INSERT INTO passkey_tokens (token, account_id, challenge, user_id, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = database.Pool.Exec(r.Context(), query, token, req.AccountID, challenge, userID, expiresAt)
	if err != nil {
		log.Printf("ERROR: Failed to save passkey token: %v", err)
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("AUDIT: Passkey token generated: %s for account %s", token, req.AccountID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

// Handler: GET /tokens/{token}
func getTargetAccountHandler(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	var accountID string
	var expiresAt time.Time
	var used bool
	query := "SELECT account_id, expires_at, used FROM passkey_tokens WHERE token = $1"
	err := database.Pool.QueryRow(r.Context(), query, token).Scan(&accountID, &expiresAt, &used)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, `{"message":"Token not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	if used {
		http.Error(w, `{"message":"Token already used"}`, http.StatusBadRequest)
		return
	}

	if time.Now().After(expiresAt) {
		http.Error(w, `{"message":"Token expired"}`, http.StatusBadRequest)
		return
	}

	// Fetch account currency for Display
	var currency string
	err = database.Pool.QueryRow(r.Context(), "SELECT currency FROM financial_accounts WHERE id = $1", accountID).Scan(&currency)
	if err != nil {
		http.Error(w, `{"message":"Target account metadata not found"}`, http.StatusNotFound)
		return
	}

	// Mask account ID for privacy
	maskedAccountID := maskUUID(accountID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"account_id": maskedAccountID,
		"currency":   currency,
	})
}

// Handler: GET /register/begin
func startRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, `{"message":"Missing token parameter"}`, http.StatusBadRequest)
		return
	}

	var accountID string
	var expiresAt time.Time
	var used bool
	err := database.Pool.QueryRow(r.Context(), "SELECT account_id, expires_at, used FROM passkey_tokens WHERE token = $1", token).Scan(&accountID, &expiresAt, &used)
	if err != nil {
		http.Error(w, `{"message":"Token invalid"}`, http.StatusNotFound)
		return
	}

	if used || time.Now().After(expiresAt) {
		http.Error(w, `{"message":"Token expired or already used"}`, http.StatusBadRequest)
		return
	}

	// Load existing credentials for the user (to avoid registering duplicates)
	existingCreds, err := wl.LoadUserCredentials(r.Context(), database.Pool, accountID)
	if err != nil {
		log.Printf("ERROR: Failed to load user credentials: %v", err)
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Build WebAuthn User representation
	user := &wl.PasskeyUser{
		ID:          []byte(accountID), // Use target account_id as binary user ID
		Name:        accountID,
		DisplayName: "Compte " + accountID[:8],
		Credentials: existingCreds,
	}

	// Generate WebAuthn options
	options, sessionData, err := webAuthn.BeginRegistration(user)
	if err != nil {
		log.Printf("ERROR: WebAuthn BeginRegistration failed: %v", err)
		http.Error(w, `{"message":"Failed to generate options"}`, http.StatusInternalServerError)
		return
	}

	// Save sessionData (JSON format) to database so the finish step can verify it
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Save WebAuthn session in the token table
	_, err = database.Pool.Exec(r.Context(), "UPDATE passkey_tokens SET challenge = $1, user_id = $2 WHERE token = $3", string(sessionJSON), sessionData.UserID, token)
	if err != nil {
		log.Printf("ERROR: Failed to update token challenge: %v", err)
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// Handler: POST /register/finish
func finishRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, `{"message":"Missing token parameter"}`, http.StatusBadRequest)
		return
	}

	var accountID string
	var expiresAt time.Time
	var used bool
	var sessionJSON string
	err := database.Pool.QueryRow(r.Context(), "SELECT account_id, expires_at, used, challenge FROM passkey_tokens WHERE token = $1", token).Scan(&accountID, &expiresAt, &used, &sessionJSON)
	if err != nil {
		http.Error(w, `{"message":"Token invalid"}`, http.StatusNotFound)
		return
	}

	if used || time.Now().After(expiresAt) {
		http.Error(w, `{"message":"Token expired or already used"}`, http.StatusBadRequest)
		return
	}

	if sessionJSON == "placeholder" {
		http.Error(w, `{"message":"Registration was not properly initiated"}`, http.StatusBadRequest)
		return
	}

	// Deserialize WebAuthn SessionData
	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Read and log request body for debugging
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // restore body for parsing
	log.Printf("DEBUG: finishRegistrationHandler - Host: %q, Origin Header: %q, X-Forwarded-Proto: %q", r.Host, r.Header.Get("Origin"), r.Header.Get("X-Forwarded-Proto"))
	log.Printf("DEBUG: finishRegistrationHandler - Raw JSON Payload: %s", string(bodyBytes))


	// Load existing credentials
	existingCreds, err := wl.LoadUserCredentials(r.Context(), database.Pool, accountID)
	if err != nil {
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	user := &wl.PasskeyUser{
		ID:          []byte(accountID),
		Name:        accountID,
		DisplayName: "Compte " + accountID[:8],
		Credentials: existingCreds,
	}

	// Parse WebAuthn response and finish registration
	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		var protocolErr *protocol.Error
		if errors.As(err, &protocolErr) {
			log.Printf("ERROR: WebAuthn FinishRegistration failed: Type=%q, Details=%q, DevInfo=%q", protocolErr.Type, protocolErr.Details, protocolErr.DevInfo)
		} else {
			log.Printf("ERROR: WebAuthn FinishRegistration failed: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
		return
	}

	// Save new credential to database
	err = wl.SaveUserCredential(r.Context(), database.Pool, accountID, credential)
	if err != nil {
		log.Printf("ERROR: Failed to save user credential: %v", err)
		http.Error(w, `{"message":"Failed to save Passkey"}`, http.StatusInternalServerError)
		return
	}

	// Mark token as used to ensure single-use
	_, err = database.Pool.Exec(r.Context(), "UPDATE passkey_tokens SET used = true WHERE token = $1", token)
	if err != nil {
		log.Printf("ERROR: Failed to mark token as used: %v", err)
	}

	log.Printf("AUDIT: Passkey registered successfully for account %s", accountID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Passkey linked successfully!"})
}

// Handler: GET /auth/begin
func startLoginHandler(w http.ResponseWriter, r *http.Request) {
	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		http.Error(w, `{"message":"Missing account_id parameter"}`, http.StatusBadRequest)
		return
	}

	// Load user credentials
	existingCreds, err := wl.LoadUserCredentials(r.Context(), database.Pool, accountID)
	if err != nil {
		log.Printf("ERROR: Failed to load user credentials: %v", err)
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	if len(existingCreds) == 0 {
		http.Error(w, `{"message":"No credentials registered for this account"}`, http.StatusNotFound)
		return
	}

	user := &wl.PasskeyUser{
		ID:          []byte(accountID),
		Name:        accountID,
		DisplayName: "Compte " + accountID[:8],
		Credentials: existingCreds,
	}

	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Printf("ERROR: WebAuthn BeginLogin failed: %v", err)
		http.Error(w, `{"message":"Failed to generate login options"}`, http.StatusInternalServerError)
		return
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(15 * time.Minute)
	sessionID := uuidStr()
	query := `
		INSERT INTO passkey_login_sessions (id, account_id, challenge, user_id, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = database.Pool.Exec(r.Context(), query, sessionID, accountID, string(sessionJSON), sessionData.UserID, expiresAt)
	if err != nil {
		log.Printf("ERROR: Failed to save login session: %v", err)
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"options":    options,
		"session_id": sessionID,
	})
}

// Handler: POST /auth/finish
func finishLoginHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	portalSessionID := r.URL.Query().Get("portal_session_id")
	if sessionID == "" {
		http.Error(w, `{"message":"Missing session_id parameter"}`, http.StatusBadRequest)
		return
	}

	var accountID string
	var sessionJSON string
	var expiresAt time.Time

	query := "SELECT account_id, challenge, expires_at FROM passkey_login_sessions WHERE id = $1"
	err := database.Pool.QueryRow(r.Context(), query, sessionID).Scan(&accountID, &sessionJSON, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, `{"message":"Session not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	if time.Now().After(expiresAt) {
		http.Error(w, `{"message":"Session expired"}`, http.StatusBadRequest)
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	existingCreds, err := wl.LoadUserCredentials(r.Context(), database.Pool, accountID)
	if err != nil {
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	user := &wl.PasskeyUser{
		ID:          []byte(accountID),
		Name:        accountID,
		DisplayName: "Compte " + accountID[:8],
		Credentials: existingCreds,
	}

	credential, err := webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Printf("ERROR: WebAuthn FinishLogin failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
		return
	}

	_, err = database.Pool.Exec(r.Context(), "UPDATE account_passkeys SET sign_counter = $1 WHERE credential_id = $2", int64(credential.Authenticator.SignCount), credential.ID)
	if err != nil {
		log.Printf("ERROR: Failed to update sign counter: %v", err)
	}

	_, _ = database.Pool.Exec(r.Context(), "DELETE FROM passkey_login_sessions WHERE id = $1", sessionID)

	if portalSessionID != "" {
		portalURL := os.Getenv("PORTAL_SERVICE_URL")
		if portalURL == "" {
			portalURL = "http://portal-service.railway.internal"
		}

		log.Printf("AUDIT: Notifying portal of successful passkey verification for account %s, session %s", accountID, portalSessionID)

		notifyReq, err := json.Marshal(map[string]string{
			"portal_session_id": portalSessionID,
			"account_id":        accountID,
		})
		if err == nil {
			claims := &Claims{
				Role: "MANAGER",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Minute)),
					Issuer:    "passkey-service",
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(jwtSecretKey)
			if err == nil {
				client := &http.Client{Timeout: 5 * time.Second}
				req, err := http.NewRequest("POST", portalURL+"/internal/verify-link", bytes.NewBuffer(notifyReq))
				if err == nil {
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Authorization", "Bearer "+tokenString)
					resp, err := client.Do(req)
					if err != nil {
						log.Printf("ERROR: Failed to notify portal service: %v", err)
					} else {
						defer resp.Body.Close()
						if resp.StatusCode != http.StatusOK {
							body, _ := io.ReadAll(resp.Body)
							log.Printf("ERROR: Portal service returned status %d: %s", resp.StatusCode, string(body))
						} else {
							log.Printf("AUDIT: Portal service successfully notified for session %s", portalSessionID)
						}
					}
				}
			}
		}
	}

	log.Printf("AUDIT: Passkey login verified successfully for account %s", accountID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Passkey verified successfully!"})
}

// Helpers
func uuidStr() string {
	// Simple UUIDv4 generation for database insert fallback
	ctx := context.Background()
	var uuid string
	_ = database.Pool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&uuid)
	return uuid
}

func maskUUID(id string) string {
	if len(id) < 8 {
		return id
	}
	return id[:4] + "-••••-••••-••••-" + id[len(id)-4:]
}
