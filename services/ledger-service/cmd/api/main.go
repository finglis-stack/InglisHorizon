package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/finglis-stack/InglisHorizon/services/ledger-service/internal/models"
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
