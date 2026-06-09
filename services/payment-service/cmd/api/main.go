package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"payment-service/internal/processor"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	log.Println("Starting Payment Service...")

	accountDBURL := os.Getenv("ACCOUNT_DB_URL")
	if accountDBURL == "" {
		// Fallback to DATABASE_URL if the same DB is used or if not set (for testing)
		accountDBURL = os.Getenv("DATABASE_URL")
	}
	ledgerDBURL := os.Getenv("LEDGER_DB_URL")
	if ledgerDBURL == "" {
		ledgerDBURL = os.Getenv("DATABASE_URL")
	}

	if accountDBURL == "" || ledgerDBURL == "" {
		log.Fatal("FATAL: ACCOUNT_DB_URL and LEDGER_DB_URL must be set")
	}

	// Connect to Account DB
	accountDB, err := pgxpool.New(context.Background(), accountDBURL)
	if err != nil {
		log.Fatalf("Failed to connect to Account DB: %v", err)
	}
	defer accountDB.Close()

	// Connect to Ledger DB
	ledgerDB, err := pgxpool.New(context.Background(), ledgerDBURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ledger DB: %v", err)
	}
	defer ledgerDB.Close()

	// Initialize the payment processor
	proc := processor.NewPaymentProcessor(accountDB, ledgerDB)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("POST /payments/init", func(w http.ResponseWriter, r *http.Request) {
		// In a real app, you would add authentication middleware here
		// For example, verifying a JWT token of the payer
		
		var req processor.PaymentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
			return
		}

		if req.PayerEmail == "" || req.ToAccountID == "" || req.Amount <= 0 {
			http.Error(w, `{"message":"Missing fields or invalid amount"}`, http.StatusBadRequest)
			return
		}

		if req.IdempotencyKey == "" {
			req.IdempotencyKey = uuid.NewString() // Auto-generate if not provided
		}

		// Enqueue the payment for asynchronous processing
		proc.EnqueuePayment(req)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202 Accepted means processing has started async
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Payment processing started",
			"status": "PROCESSING",
			"idempotency_key": req.IdempotencyKey,
		})
	})

	mux.HandleFunc("POST /payments/deposit", func(w http.ResponseWriter, r *http.Request) {
		var req processor.PaymentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
			return
		}

		if req.ToAccountID == "" || req.Amount <= 0 {
			http.Error(w, `{"message":"Missing account ID or invalid amount"}`, http.StatusBadRequest)
			return
		}

		req.Type = "DEPOSIT"

		if req.IdempotencyKey == "" {
			req.IdempotencyKey = uuid.NewString() // Auto-generate if not provided
		}

		proc.EnqueuePayment(req)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Deposit processing started",
			"status": "PROCESSING",
			"idempotency_key": req.IdempotencyKey,
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Payment Service running on port %s", port)
	if err := http.ListenAndServe("0.0.0.0:"+port, mux); err != nil {
		log.Fatal(err)
	}
}
