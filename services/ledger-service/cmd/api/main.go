package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/finglis-stack/InglisHorizon/services/ledger-service/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool
var jwtSecretKey []byte
var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func isValidUUID(id string) bool {
	return uuidRegex.MatchString(id)
}

// CORS middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", os.Getenv("ALLOWED_ORIGINS"))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// JWT authentication middleware
func authMiddleware(requiredRoles []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
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
	jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if os.Getenv("JWT_SECRET_KEY") == "" {
		log.Fatal("FATAL: JWT_SECRET_KEY is not set")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	var err error
	pool, err = pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer pool.Close()

	if err := models.InitDB(context.Background(), pool); err != nil {
		log.Fatalf("Failed to initialize ledger tables: %v", err)
	}

	mux := http.NewServeMux()

	// Health check (no auth needed)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// POST /ledger/accounts - Create financial account (MANAGER only)
	mux.HandleFunc("POST /ledger/accounts", authMiddleware([]string{"MANAGER"}, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OwnerID     string  `json:"owner_id"`
			Currency    string  `json:"currency"`
			Type        string  `json:"account_type"`
			APR         float64 `json:"apr"`
			CreditLimit int64   `json:"credit_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
			return
		}

		if !isValidUUID(req.OwnerID) {
			http.Error(w, `{"message":"Invalid owner_id format"}`, http.StatusBadRequest)
			return
		}

		id, err := models.CreateAccount(r.Context(), pool, req.OwnerID, req.Currency, req.Type, req.APR, req.CreditLimit)
		if err != nil {
			log.Printf("ERROR: Failed to create account: %v", err)
			http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("AUDIT: Financial account created: %s for owner %s", id, req.OwnerID)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": id})
	}))

	// GET /ledger/accounts/{id} - Get account details and balance (authenticated)
	mux.HandleFunc("GET /ledger/accounts/{id}", authMiddleware([]string{"MANAGER", "SUPPORT"}, func(w http.ResponseWriter, r *http.Request) {
		accountID := r.PathValue("id")
		if !isValidUUID(accountID) {
			http.Error(w, `{"message":"Invalid account ID format"}`, http.StatusBadRequest)
			return
		}

		acc, err := models.GetAccount(r.Context(), pool, accountID)
		if err != nil {
			log.Printf("ERROR: Failed to get account metadata for %s: %v", accountID, err)
			http.Error(w, `{"message":"Account not found"}`, http.StatusNotFound)
			return
		}

		balance, err := models.GetBalance(r.Context(), pool, accountID)
		if err != nil {
			log.Printf("ERROR: Failed to get balance for %s: %v", accountID, err)
			http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":           acc.ID,
			"currency":     acc.Currency,
			"account_type": acc.Type,
			"status":       acc.Status,
			"apr":          acc.APR,
			"credit_limit": acc.CreditLimit,
			"balance":      balance,
			"account_id":   acc.ID,
			"owner_id":     acc.OwnerID,
			"name":         acc.Name,
		})
	}))

	// GET /ledger/owners/{owner_id}/accounts - List accounts by owner (authenticated)
	mux.HandleFunc("GET /ledger/owners/{owner_id}/accounts", authMiddleware([]string{"MANAGER", "SUPPORT"}, func(w http.ResponseWriter, r *http.Request) {
		ownerID := r.PathValue("owner_id")
		if !isValidUUID(ownerID) {
			http.Error(w, `{"message":"Invalid owner ID format"}`, http.StatusBadRequest)
			return
		}

		accounts, err := models.GetAccountsByOwner(r.Context(), pool, ownerID)
		if err != nil {
			log.Printf("ERROR: Failed to retrieve accounts for owner %s: %v", ownerID, err)
			http.Error(w, `{"message":"Failed to retrieve accounts"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(accounts)
	}))

	// GET /ledger/accounts/{id}/transactions - Get transaction history (authenticated)
	mux.HandleFunc("GET /ledger/accounts/{id}/transactions", authMiddleware([]string{"MANAGER", "SUPPORT"}, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !isValidUUID(id) {
			http.Error(w, `{"message":"Invalid account ID format"}`, http.StatusBadRequest)
			return
		}

		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit < 1 || limit > 100 {
			limit = 10
		}
		offset := (page - 1) * limit

		txs, err := models.GetTransactions(r.Context(), pool, id, limit, offset)
		if err != nil {
			log.Printf("ERROR: Failed to retrieve transactions for %s: %v", id, err)
			http.Error(w, `{"message":"Failed to retrieve transactions"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"page":         page,
			"limit":        limit,
			"transactions": txs,
		})
	}))

	// POST /ledger/transfer - Transfer funds (MANAGER only)
	mux.HandleFunc("POST /ledger/transfer", authMiddleware([]string{"MANAGER"}, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			FromAccount    string `json:"from_account"`
			ToAccount      string `json:"to_account"`
			Amount         int64  `json:"amount"`
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
			return
		}

		if !isValidUUID(req.FromAccount) || !isValidUUID(req.ToAccount) {
			http.Error(w, `{"message":"Invalid account ID format"}`, http.StatusBadRequest)
			return
		}

		err := models.Transfer(r.Context(), pool, req.FromAccount, req.ToAccount, req.Amount, req.IdempotencyKey)
		if err != nil {
			log.Printf("ERROR: Transfer failed from %s to %s: %v", req.FromAccount, req.ToAccount, err)
			http.Error(w, `{"message":"Transfer failed"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("AUDIT: Transfer of %d cents from %s to %s", req.Amount, req.FromAccount, req.ToAccount)
		json.NewEncoder(w).Encode(map[string]string{"message": "Transfer successful"})
	}))

	// POST /ledger/accounts/{id}/close - Close account (MANAGER only)
	mux.HandleFunc("POST /ledger/accounts/{id}/close", authMiddleware([]string{"MANAGER"}, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !isValidUUID(id) {
			http.Error(w, `{"message":"Invalid account ID format"}`, http.StatusBadRequest)
			return
		}

		err := models.CloseAccount(r.Context(), pool, id)
		if err != nil {
			log.Printf("ERROR: Failed to close account %s: %v", id, err)
			http.Error(w, `{"message":"Failed to close account"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("AUDIT: Account %s closed", id)
		json.NewEncoder(w).Encode(map[string]string{"message": "Account successfully marked as CLOSED"})
	}))

	// POST /ledger/cron/interest - Protected by CRON_SECRET_KEY
	mux.HandleFunc("POST /ledger/cron/interest", func(w http.ResponseWriter, r *http.Request) {
		cronSecret := os.Getenv("CRON_SECRET_KEY")
		if cronSecret == "" {
			http.Error(w, `{"message":"Cron endpoint not configured"}`, http.StatusServiceUnavailable)
			return
		}
		authHeader := r.Header.Get("X-Cron-Secret")
		if authHeader != cronSecret {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		batchID := time.Now().Format("20060102")
		err := models.AccrueDailyInterest(r.Context(), pool, batchID)
		if err != nil {
			log.Printf("ERROR: Failed to run daily interest: %v", err)
			http.Error(w, `{"message":"Failed to run daily interest"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("AUDIT: Daily interest processed, batch %s", batchID)
		json.NewEncoder(w).Encode(map[string]string{"message": "Daily interest processed successfully", "batch_id": batchID})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8483"
	}
	log.Printf("Ledger Service running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, corsMiddleware(mux)))
}
