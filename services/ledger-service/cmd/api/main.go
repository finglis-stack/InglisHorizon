package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/finglis-stack/InglisHorizon/services/ledger-service/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

func main() {
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

	// POST /ledger/accounts
	mux.HandleFunc("POST /ledger/accounts", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OwnerID  string  `json:"owner_id"`
			Currency string  `json:"currency"`
			Type     string  `json:"account_type"`
			APR      float64 `json:"apr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
			return
		}

		id, err := models.CreateAccount(r.Context(), pool, req.OwnerID, req.Currency, req.Type, req.APR)
		if err != nil {
			http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": id})
	})

	// GET /ledger/accounts/{id}/balance
	mux.HandleFunc("GET /ledger/accounts/", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/ledger/accounts/"):]
		// expecting /ledger/accounts/{id}/balance
		if len(id) < 36 {
			http.Error(w, `{"message":"Invalid account ID"}`, http.StatusBadRequest)
			return
		}
		accountID := id[:36]

		balance, err := models.GetBalance(r.Context(), pool, accountID)
		if err != nil {
			http.Error(w, `{"message":"Account not found or error"}`, http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"account_id": accountID,
			"balance":    balance, // in cents
		})
	})

	// GET /ledger/accounts/owner/{owner_id}
	mux.HandleFunc("GET /ledger/accounts/owner/{owner_id}", func(w http.ResponseWriter, r *http.Request) {
		ownerID := r.PathValue("owner_id")
		if ownerID == "" {
			http.Error(w, `{"message":"Invalid owner ID"}`, http.StatusBadRequest)
			return
		}
		accounts, err := models.GetAccountsByOwner(r.Context(), pool, ownerID)
		if err != nil {
			http.Error(w, `{"message":"Failed to retrieve accounts", "error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(accounts)
	})

	// GET /ledger/accounts/{id}/transactions
	mux.HandleFunc("GET /ledger/accounts/{id}/transactions", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, `{"message":"Invalid account ID"}`, http.StatusBadRequest)
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
			http.Error(w, `{"message":"Failed to retrieve transactions", "error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"page":         page,
			"limit":        limit,
			"transactions": txs,
		})
	})

	// POST /ledger/transfer
	mux.HandleFunc("POST /ledger/transfer", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			FromAccount    string `json:"from_account"`
			ToAccount      string `json:"to_account"`
			Amount         int64  `json:"amount"` // in cents
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
			return
		}

		err := models.Transfer(r.Context(), pool, req.FromAccount, req.ToAccount, req.Amount, req.IdempotencyKey)
		if err != nil {
			http.Error(w, `{"message":"Transfer failed", "error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"message": "Transfer successful"})
	})

	// POST /ledger/accounts/{id}/close
	mux.HandleFunc("POST /ledger/accounts/{id}/close", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, `{"message":"Invalid account ID"}`, http.StatusBadRequest)
			return
		}
		err := models.CloseAccount(r.Context(), pool, id)
		if err != nil {
			http.Error(w, `{"message":"Failed to close account", "error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"message": "Account successfully marked as CLOSED"})
	})

	// POST /ledger/cron/interest
	mux.HandleFunc("POST /ledger/cron/interest", func(w http.ResponseWriter, r *http.Request) {
		// In a real system, verify a secret token or master key to ensure only authorized callers trigger this.
		batchID := time.Now().Format("20060102")
		err := models.AccrueDailyInterest(r.Context(), pool, batchID)
		if err != nil {
			http.Error(w, `{"message":"Failed to run daily interest accrue"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"message": "Daily interest processed successfully", "batch_id": batchID})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8483"
	}
	log.Printf("Ledger Service running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
