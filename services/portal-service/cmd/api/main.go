package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"portal-service/internal/db"
)

var (
	database       *db.DB
	jwtSecretKey   []byte
	accountDBPool  *pgxpool.Pool
)

type PortalClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type InternalClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func main() {
	log.Println("Starting Inglis Horizon Portal Service...")

	jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if os.Getenv("JWT_SECRET_KEY") == "" {
		log.Fatal("FATAL: JWT_SECRET_KEY is not set")
	}

	var err error
	database, err = db.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to Portal Database: %v", err)
	}
	defer database.Close()

	accountDBURL := os.Getenv("ACCOUNT_DB_URL")
	if accountDBURL != "" {
		accountDBPool, err = pgxpool.New(context.Background(), accountDBURL)
		if err != nil {
			log.Printf("WARNING: Failed to connect to Account Database: %v", err)
		} else {
			defer accountDBPool.Close()
			log.Println("Connected to Account Database successfully")
		}
	} else {
		log.Println("WARNING: ACCOUNT_DB_URL is not set")
	}

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Static Web Frontend Routing
	workDir, _ := os.Getwd()
	staticDir := workDir + "/web/static"
	log.Printf("Serving static portal files from: %s", staticDir)
	
	// Health Check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Server-level routing to serve pages
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, staticDir+"/dashboard.html")
	})
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, staticDir+"/login.html")
	})
	r.Get("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, staticDir+"/register.html")
	})
	r.Get("/account", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, staticDir+"/account.html")
	})
	
	// Helper to serve CSS/images or JS assets if needed
	fileServer(r, "/assets", http.Dir(staticDir))

	// API Routes (Public)
	r.Post("/api/register", registerHandler)
	r.Post("/api/login", loginHandler)
	r.Post("/api/logout", logoutHandler)

	// API Routes (Authenticated)
	r.Group(func(r chi.Router) {
		r.Use(portalAuthMiddleware)
		r.Get("/api/me", meHandler)
		r.Get("/api/accounts", listLinkedAccountsHandler)
		r.Get("/api/accounts/{id}", getAccountDetailsHandler)
		r.Get("/api/accounts/{id}/transactions", getAccountTransactionsHandler)
		r.Post("/api/transfer", transferFundsHandler)
		r.Post("/api/link/begin", beginLinkHandler)
		r.Get("/api/link/callback", linkCallbackHandler)
	})

	// Internal Webhook (Secured with MANAGER token from passkey-service)
	r.Post("/internal/verify-link", verifyLinkWebhookHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Portal Service running on port %s", port)
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

// Middleware: Authenticate Portal User using Cookie
func portalAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("portal_session")
		if err != nil {
			http.Error(w, `{"message":"Unauthorized: Session cookie missing"}`, http.StatusUnauthorized)
			return
		}

		claims := &PortalClaims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, `{"message":"Unauthorized: Invalid session"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "username", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Handler: POST /api/register
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, `{"message":"Missing fields"}`, http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	query := "INSERT INTO end_users (username, email, password_hash) VALUES ($1, $2, $3)"
	_, err = database.Pool.Exec(r.Context(), query, req.Username, req.Email, string(hash))
	if err != nil {
		log.Printf("ERROR: Failed to register user: %v", err)
		http.Error(w, `{"message":"Username or Email already exists"}`, http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Registration successful!"})
}

// Handler: POST /api/login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
		return
	}

	var userID string
	var email string
	var hash string
	var username string

	query := "SELECT id, username, email, password_hash FROM end_users WHERE username = $1 OR email = $1"
	err := database.Pool.QueryRow(r.Context(), query, req.Username).Scan(&userID, &username, &email, &hash)
	if err != nil {
		http.Error(w, `{"message":"Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		http.Error(w, `{"message":"Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// Generate JWT Portal Session
	expiration := time.Now().Add(24 * time.Hour)
	claims := &PortalClaims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			Issuer:    "portal-service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwtSecretKey)
	if err != nil {
		http.Error(w, `{"message":"Failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	// Set session Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "portal_session",
		Value:    tokenStr,
		Expires:  expiration,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true if HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful!"})
}

// Handler: POST /api/logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "portal_session",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logout successful!"})
}

// Handler: GET /api/me
func meHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	json.NewEncoder(w).Encode(map[string]string{"username": username})
}

// Helper: Make internal signed request to ledger-service
func fetchLedgerData(ctx context.Context, endpoint string, result interface{}) error {
	ledgerURL := os.Getenv("LEDGER_SERVICE_URL")
	if ledgerURL == "" {
		ledgerURL = "http://ledger-service.railway.internal"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", ledgerURL+endpoint, nil)
	if err != nil {
		return err
	}

	// Sign internally with shared JWT key
	claims := &InternalClaims{
		Role: "MANAGER",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Minute)),
			Issuer:    "portal-service",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ledger-service returned code %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(result)
}

// Handler: GET /api/accounts
func listLinkedAccountsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	rows, err := database.Pool.Query(r.Context(), "SELECT account_id FROM user_linked_accounts WHERE user_id = $1 ORDER BY linked_at DESC", userID)
	if err != nil {
		http.Error(w, `{"message":"Failed to query linked accounts"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type LedgerAccount struct {
		ID          string  `json:"id"`
		Currency    string  `json:"currency"`
		Type        string  `json:"account_type"`
		Status      string  `json:"status"`
		APR         float64 `json:"apr"`
		CreditLimit int64   `json:"credit_limit"`
	}

	type AccountWithBalance struct {
		LedgerAccount
		Balance int64 `json:"balance"`
	}

	accounts := []AccountWithBalance{}

	for rows.Next() {
		var accountID string
		if err := rows.Scan(&accountID); err != nil {
			continue
		}

		// 1. Fetch details from ledger-service
		var details LedgerAccount
		err = fetchLedgerData(r.Context(), "/ledger/accounts/"+accountID, &details)
		if err != nil {
			log.Printf("ERROR: Failed to fetch details for account %s: %v", accountID, err)
			continue
		}

		// 2. Fetch balance
		var balResponse struct {
			Balance int64 `json:"balance"`
		}
		err = fetchLedgerData(r.Context(), "/ledger/accounts/"+accountID, &balResponse)
		if err != nil {
			log.Printf("ERROR: Failed to fetch balance for account %s: %v", accountID, err)
			continue
		}

		accounts = append(accounts, AccountWithBalance{
			LedgerAccount: details,
			Balance:       balResponse.Balance,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(accounts)
}

// Handler: GET /api/accounts/{id}/transactions
func getAccountTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	accountID := chi.URLParam(r, "id")
	userID := r.Context().Value("user_id").(string)

	// Verify the user actually owns this link
	var exists bool
	err := database.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM user_linked_accounts WHERE user_id = $1 AND account_id = $2)", userID, accountID).Scan(&exists)
	if err != nil || !exists {
		http.Error(w, `{"message":"Forbidden: Account not linked to this profile"}`, http.StatusForbidden)
		return
	}

	var txResponse interface{}
	err = fetchLedgerData(r.Context(), "/ledger/accounts/"+accountID+"/transactions?limit=20", &txResponse)
	if err != nil {
		log.Printf("ERROR: Failed to fetch transactions for account %s: %v", accountID, err)
		http.Error(w, `{"message":"Failed to fetch transaction history"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(txResponse)
}

// Handler: POST /api/link/begin
func beginLinkHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

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

	// 1. Create link session in portal-db
	expiresAt := time.Now().Add(15 * time.Minute)
	var sessionID string
	query := `
		INSERT INTO portal_link_sessions (user_id, account_id, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id
	`
	err := database.Pool.QueryRow(r.Context(), query, userID, req.AccountID, expiresAt).Scan(&sessionID)
	if err != nil {
		log.Printf("ERROR: Failed to save portal link session: %v", err)
		http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// 2. Build redirect URL to passkey-service verify.html
	passkeyURL := os.Getenv("PASSKEY_SERVICE_URL")
	if passkeyURL == "" {
		passkeyURL = "https://pass.inglishorizon.com"
	}
	
	// Constructing the full redirect URL
	portalDomain := os.Getenv("PORTAL_SERVICE_DOMAIN")
	if portalDomain == "" {
		portalDomain = "https://portal.inglishorizon.com"
	}
	callbackURL := portalDomain + "/api/link/callback"

	redirectLink := fmt.Sprintf("%s/link/verify.html?account_id=%s&portal_session_id=%s&redirect_url=%s",
		passkeyURL, req.AccountID, sessionID, callbackURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": redirectLink,
	})
}

// Handler: GET /api/link/callback
func linkCallbackHandler(w http.ResponseWriter, r *http.Request) {
	portalSessionID := r.URL.Query().Get("portal_session_id")
	status := r.URL.Query().Get("status")

	if portalSessionID == "" || status != "success" {
		http.Redirect(w, r, "/?error=verification_failed", http.StatusSeeOther)
		return
	}

	// 1. Load session and verify it has been marked as verified by the webhook
	var userID string
	var accountID string
	var verified bool
	var expiresAt time.Time

	query := "SELECT user_id, account_id, verified, expires_at FROM portal_link_sessions WHERE id = $1"
	err := database.Pool.QueryRow(r.Context(), query, portalSessionID).Scan(&userID, &accountID, &verified, &expiresAt)
	if err != nil {
		http.Redirect(w, r, "/?error=session_invalid", http.StatusSeeOther)
		return
	}

	if time.Now().After(expiresAt) {
		http.Redirect(w, r, "/?error=session_expired", http.StatusSeeOther)
		return
	}

	if !verified {
		http.Redirect(w, r, "/?error=not_verified", http.StatusSeeOther)
		return
	}

	// 2. Add to linked accounts
	linkQuery := `
		INSERT INTO user_linked_accounts (user_id, account_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, account_id) DO NOTHING
	`
	_, err = database.Pool.Exec(r.Context(), linkQuery, userID, accountID)
	if err != nil {
		log.Printf("ERROR: Failed to save link association: %v", err)
		http.Redirect(w, r, "/?error=linking_db_error", http.StatusSeeOther)
		return
	}

	// Clean up link session
	_, _ = database.Pool.Exec(r.Context(), "DELETE FROM portal_link_sessions WHERE id = $1", portalSessionID)

	log.Printf("AUDIT: Successfully linked account %s to portal user %s", accountID, userID)
	http.Redirect(w, r, "/?status=success", http.StatusSeeOther)
}

// Webhook Handler: POST /internal/verify-link
func verifyLinkWebhookHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Verify internal request token (JWT MANAGER auth)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims := &InternalClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if err != nil || !token.Valid || claims.Role != "MANAGER" {
		http.Error(w, `{"message":"Forbidden"}`, http.StatusForbidden)
		return
	}

	var req struct {
		PortalSessionID string `json:"portal_session_id"`
		AccountID       string `json:"account_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message":"Invalid body"}`, http.StatusBadRequest)
		return
	}

	// 2. Mark the portal link session as verified
	res, err := database.Pool.Exec(r.Context(), "UPDATE portal_link_sessions SET verified = true WHERE id = $1 AND account_id = $2", req.PortalSessionID, req.AccountID)
	if err != nil {
		log.Printf("ERROR: Failed to verify portal link session: %v", err)
		http.Error(w, `{"message":"DB Error"}`, http.StatusInternalServerError)
		return
	}

	rowsAffected := res.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, `{"message":"Session not found or mismatches account"}`, http.StatusNotFound)
		return
	}

	log.Printf("AUDIT: Webhook marked portal link session %s as verified", req.PortalSessionID)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"verified"}`))
}

// Handler: GET /api/accounts/{id}
func getAccountDetailsHandler(w http.ResponseWriter, r *http.Request) {
	accountID := chi.URLParam(r, "id")
	userID := r.Context().Value("user_id").(string)

	// Verify the user actually owns this link
	var exists bool
	err := database.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM user_linked_accounts WHERE user_id = $1 AND account_id = $2)", userID, accountID).Scan(&exists)
	if err != nil || !exists {
		http.Error(w, `{"message":"Forbidden: Account not linked to this profile"}`, http.StatusForbidden)
		return
	}

	type LedgerAccount struct {
		ID          string  `json:"id"`
		Currency    string  `json:"currency"`
		Type        string  `json:"account_type"`
		Status      string  `json:"status"`
		APR         float64 `json:"apr"`
		CreditLimit int64   `json:"credit_limit"`
		OwnerID     string  `json:"owner_id"`
	}

	type AccountWithBalance struct {
		LedgerAccount
		Balance int64 `json:"balance"`
	}

	// 1. Fetch details from ledger-service
	var details LedgerAccount
	err = fetchLedgerData(r.Context(), "/ledger/accounts/"+accountID, &details)
	if err != nil {
		log.Printf("ERROR: Failed to fetch details for account %s: %v", accountID, err)
		http.Error(w, `{"message":"Failed to fetch account metadata"}`, http.StatusInternalServerError)
		return
	}

	// 2. Fetch balance
	var balResponse struct {
		Balance int64 `json:"balance"`
	}
	err = fetchLedgerData(r.Context(), "/ledger/accounts/"+accountID, &balResponse)
	if err != nil {
		log.Printf("ERROR: Failed to fetch balance for account %s: %v", accountID, err)
		http.Error(w, `{"message":"Failed to fetch account balance"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AccountWithBalance{
		LedgerAccount: details,
		Balance:       balResponse.Balance,
	})
}

// Handler: POST /api/transfer
func transferFundsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var req struct {
		FromAccountID string `json:"from_account_id"`
		ToAccountID   string `json:"to_account_id"`
		AmountCents   int64  `json:"amount_cents"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
		return
	}

	if req.FromAccountID == "" || req.ToAccountID == "" || req.AmountCents <= 0 {
		http.Error(w, `{"message":"Invalid parameters"}`, http.StatusBadRequest)
		return
	}

	// 1. Verify the user actually owns/linked from_account_id
	var exists bool
	err := database.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM user_linked_accounts WHERE user_id = $1 AND account_id = $2)", userID, req.FromAccountID).Scan(&exists)
	if err != nil || !exists {
		http.Error(w, `{"message":"Forbidden: Source account not linked to this profile"}`, http.StatusForbidden)
		return
	}

	// 2. Fetch source account details from ledger-service to get owner_id
	type LedgerAccount struct {
		ID          string  `json:"id"`
		Currency    string  `json:"currency"`
		Type        string  `json:"account_type"`
		Status      string  `json:"status"`
		APR         float64 `json:"apr"`
		CreditLimit int64   `json:"credit_limit"`
		OwnerID     string  `json:"owner_id"`
	}
	var details LedgerAccount
	err = fetchLedgerData(r.Context(), "/ledger/accounts/"+req.FromAccountID, &details)
	if err != nil {
		log.Printf("ERROR: Failed to fetch source account details: %v", err)
		http.Error(w, `{"message":"Failed to fetch source account details"}`, http.StatusInternalServerError)
		return
	}

	if details.OwnerID == "" {
		log.Printf("ERROR: OwnerID is empty for account %s", req.FromAccountID)
		http.Error(w, `{"message":"Failed to identify account owner"}`, http.StatusInternalServerError)
		return
	}

	// 3. Look up owner email from secure_accounts in the account-service DB
	if accountDBPool == nil {
		log.Printf("ERROR: accountDBPool is not initialized")
		http.Error(w, `{"message":"Account service database unavailable"}`, http.StatusInternalServerError)
		return
	}

	var payerEmail string
	err = accountDBPool.QueryRow(r.Context(), "SELECT email FROM secure_accounts WHERE id = $1", details.OwnerID).Scan(&payerEmail)
	if err != nil {
		log.Printf("ERROR: Failed to query email for owner %s: %v", details.OwnerID, err)
		http.Error(w, `{"message":"Account owner not found in banking directory"}`, http.StatusNotFound)
		return
	}

	// 4. Send request to payment-service POST /payments/init
	paymentURL := os.Getenv("PAYMENT_SERVICE_URL")
	if paymentURL == "" {
		paymentURL = "http://payment-service.railway.internal:8080"
	}

	// Generate UUID version 4 for idempotency key
	idempotencyKey := generateUUID()

	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	payload := map[string]interface{}{
		"payer_email":     payerEmail,
		"from_account_id": req.FromAccountID,
		"to_account_id":   req.ToAccountID,
		"amount":          req.AmountCents,
		"idempotency_key": idempotencyKey,
		"type":            "PAYMENT",
		"client_ip":       clientIP,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"message":"Failed to marshal payment request"}`, http.StatusInternalServerError)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	reqInit, err := http.NewRequestWithContext(r.Context(), "POST", paymentURL+"/payments/init", strings.NewReader(string(jsonPayload)))
	if err != nil {
		http.Error(w, `{"message":"Failed to create payment service request"}`, http.StatusInternalServerError)
		return
	}
	reqInit.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(reqInit)
	if err != nil {
		log.Printf("ERROR: Payment service call failed: %v", err)
		http.Error(w, `{"message":"Failed to contact payment clearing house"}`, http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: Payment service returned code %d: %s", resp.StatusCode, string(bodyBytes))
		
		// Parse payment service error message if present
		var errResp struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(bodyBytes, &errResp); err == nil && errResp.Message != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(resp.StatusCode)
			w.Write(bodyBytes)
			return
		}
		
		http.Error(w, fmt.Sprintf(`{"message":"Payment rejected: %s"}`, string(bodyBytes)), resp.StatusCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bodyBytes)
}

func generateUUID() string {
	b := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return time.Now().Format("20060102150405") + "-1111-2222-3333-444455556666"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
