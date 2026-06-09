package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"antifraud-service/internal/analyzer"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	log.Println("Starting Antifraud Service...")

	accountDBURL := os.Getenv("ACCOUNT_DB_URL")
	if accountDBURL == "" {
		accountDBURL = os.Getenv("DATABASE_URL")
	}
	ledgerDBURL := os.Getenv("LEDGER_DB_URL")
	if ledgerDBURL == "" {
		ledgerDBURL = os.Getenv("DATABASE_URL")
	}

	if accountDBURL == "" || ledgerDBURL == "" {
		log.Fatal("FATAL: ACCOUNT_DB_URL and LEDGER_DB_URL must be set")
	}

	accountDB, err := pgxpool.New(context.Background(), accountDBURL)
	if err != nil {
		log.Fatalf("Failed to connect to Account DB: %v", err)
	}
	defer accountDB.Close()

	ledgerDB, err := pgxpool.New(context.Background(), ledgerDBURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ledger DB: %v", err)
	}
	defer ledgerDB.Close()

	fraudAnalyzer := analyzer.NewAntifraudAnalyzer(accountDB, ledgerDB)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("POST /analyze", func(w http.ResponseWriter, r *http.Request) {
		var req analyzer.AnalyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Bad request"}`, http.StatusBadRequest)
			return
		}

		resp := fraudAnalyzer.Analyze(context.Background(), req)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("GET /logs/", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Path[len("/logs/"):]
		if email == "" {
			http.Error(w, `{"message":"Missing email"}`, http.StatusBadRequest)
			return
		}

		rows, err := ledgerDB.Query(context.Background(), "SELECT id, payer_email, from_account_id, to_account_id, amount, status, reason, created_at FROM antifraud_logs WHERE payer_email = $1 ORDER BY created_at DESC LIMIT 50", email)
		if err != nil {
			http.Error(w, `{"message":"Database error"}`, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var logs []map[string]interface{}
		for rows.Next() {
			var id int
			var payerEmail, fromAcc, toAcc, status, reason string
			var amount int64
			var createdAt interface{}
			if err := rows.Scan(&id, &payerEmail, &fromAcc, &toAcc, &amount, &status, &reason, &createdAt); err == nil {
				logs = append(logs, map[string]interface{}{
					"id": id,
					"payer_email": payerEmail,
					"from_account_id": fromAcc,
					"to_account_id": toAcc,
					"amount": amount,
					"status": status,
					"reason": reason,
					"created_at": createdAt,
				})
			}
		}

		if logs == nil {
			logs = []map[string]interface{}{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Antifraud Service running on port %s", port)
	if err := http.ListenAndServe("0.0.0.0:"+port, mux); err != nil {
		log.Fatal(err)
	}
}
