package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PaymentRequest struct {
	Type           string `json:"type"` // "PAYMENT" or "DEPOSIT"
	PayerEmail     string `json:"payer_email"`
	FromAccountID  string `json:"from_account_id"`
	ToAccountID    string `json:"to_account_id"`
	Amount         int64  `json:"amount"`
	IdempotencyKey string `json:"idempotency_key"`
	ClientIP       string `json:"client_ip"`
}

type PaymentProcessor struct {
	AccountDB *pgxpool.Pool
	LedgerDB  *pgxpool.Pool
	Jobs      chan PaymentRequest
}

func NewPaymentProcessor(accountDB, ledgerDB *pgxpool.Pool) *PaymentProcessor {
	p := &PaymentProcessor{
		AccountDB: accountDB,
		LedgerDB:  ledgerDB,
		Jobs:      make(chan PaymentRequest, 1000), // Buffered channel for async jobs
	}
	// Start 10 workers for async processing
	for i := 0; i < 10; i++ {
		go p.worker(i)
	}
	return p
}

func (p *PaymentProcessor) EnqueuePayment(req PaymentRequest) {
	p.Jobs <- req
}

func (p *PaymentProcessor) worker(id int) {
	for req := range p.Jobs {
		log.Printf("[Worker %d] Processing payment %s for %s", id, req.IdempotencyKey, req.PayerEmail)
		err := p.processPayment(req)
		if err != nil {
			log.Printf("[Worker %d] Payment %s failed: %v", id, req.IdempotencyKey, err)
			// Here we could update a payment status table
		} else {
			log.Printf("[Worker %d] Payment %s SUCCESS", id, req.IdempotencyKey)
		}
	}
}

func (p *PaymentProcessor) processPayment(req PaymentRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if req.Type == "" {
		req.Type = "PAYMENT"
	}

	// Begin Transaction on Ledger DB for atomic operations
	tx, err := p.LedgerDB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin ledger transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	if req.Type == "DEPOSIT" {
		var toStatus string
		err = tx.QueryRow(ctx, "SELECT status FROM financial_accounts WHERE id = $1 FOR UPDATE", req.ToAccountID).Scan(&toStatus)
		if err != nil || toStatus == "CLOSED" {
			return fmt.Errorf("recipient account invalid or closed (ID: %s): %v", req.ToAccountID, err)
		}

		var txID string
		err = tx.QueryRow(ctx, "INSERT INTO transactions (idempotency_key, type) VALUES ($1, 'DEPOSIT') RETURNING id", req.IdempotencyKey).Scan(&txID)
		if err != nil {
			return fmt.Errorf("transaction might already exist (idempotency): %v", err)
		}

		_, err = tx.Exec(ctx, "INSERT INTO entries (transaction_id, account_id, direction, amount) VALUES ($1, $2, 'CREDIT', $3)", txID, req.ToAccountID, req.Amount)
		if err != nil {
			return fmt.Errorf("failed to create credit entry: %v", err)
		}

		return tx.Commit(ctx)
	}

	// 1. Verification Phase: Find the user in Account DB (particulier)
	var ownerID string
	err = p.AccountDB.QueryRow(ctx, "SELECT id FROM secure_accounts WHERE email = $1", req.PayerEmail).Scan(&ownerID)
	if err != nil {
		// Payer not found in Account DB. Check if payer is a merchant.
		merchantURL := os.Getenv("MERCHANT_SERVICE_URL")
		if merchantURL == "" {
			merchantURL = "https://merchant-service-production-e5be.up.railway.app"
		}
		
		merchantSearchURL := fmt.Sprintf("%s/merchants/search?q=%s", merchantURL, req.PayerEmail)
		httpReq, httpErr := http.NewRequestWithContext(ctx, "GET", merchantSearchURL, nil)
		if httpErr != nil {
			return fmt.Errorf("payer account not found in Account DB: %v", err)
		}
		
		client := &http.Client{Timeout: 5 * time.Second}
		resp, httpErr := client.Do(httpReq)
		if httpErr != nil || resp.StatusCode != http.StatusOK {
			if resp != nil { resp.Body.Close() }
			return fmt.Errorf("payer account not found in Account DB nor Merchant DB: %v", err)
		}
		
		var mResult map[string]interface{}
		jsonErr := json.NewDecoder(resp.Body).Decode(&mResult)
		resp.Body.Close()
		if jsonErr != nil {
			return fmt.Errorf("failed to decode merchant response: %v", jsonErr)
		}
		
		var ok bool
		ownerID, ok = mResult["id"].(string)
		if !ok || ownerID == "" {
			return fmt.Errorf("invalid merchant ID returned from Merchant DB")
		}
	}

	// Anti-Fraud Placeholder: Here we could call an anti-fraud service
	// if err := CallAntiFraudService(req, ownerID); err != nil { return err }

	// 2. Account Phase: Find the payer's account
	var fromAccountID string
	var status string
	var accType string
	var fromCurrency string

	if req.FromAccountID != "" {
		fromAccountID = req.FromAccountID
		err = tx.QueryRow(ctx, "SELECT account_type, status, currency FROM financial_accounts WHERE id = $1 AND owner_id = $2 FOR UPDATE", fromAccountID, ownerID).Scan(&accType, &status, &fromCurrency)
		if err != nil || status == "CLOSED" {
			return fmt.Errorf("provided sender account invalid or closed")
		}
	} else {
		err = tx.QueryRow(ctx, "SELECT id, account_type, status, currency FROM financial_accounts WHERE owner_id = $1 AND account_type = 'DEPOSIT' AND status != 'CLOSED' LIMIT 1 FOR UPDATE", ownerID).Scan(&fromAccountID, &accType, &status, &fromCurrency)
		if err != nil {
			return fmt.Errorf("payer has no active DEPOSIT account in Ledger DB")
		}
	}

	// Check Balance for DEPOSIT account (CREDIT accounts can be overdrawn up to a limit, but we'll assume no limit here or handled elsewhere)
	if accType == "DEPOSIT" {
		var balance int64
		balQuery := `
			SELECT 
				COALESCE(SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END), 0) -
				COALESCE(SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END), 0)
			FROM entries WHERE account_id = $1
		`
		err = tx.QueryRow(ctx, balQuery, fromAccountID).Scan(&balance)
		if err != nil {
			return fmt.Errorf("failed to check balance: %v", err)
		}
		if balance < req.Amount {
			return fmt.Errorf("insufficient funds (balance: %d, requested: %d)", balance, req.Amount)
		}
	}

	// 2.5 Anti-Fraud Engine via HTTP
	antifraudURL := os.Getenv("ANTIFRAUD_SERVICE_URL")
	if antifraudURL != "" {
		payload, _ := json.Marshal(req)
		httpReq, err := http.NewRequestWithContext(ctx, "POST", antifraudURL+"/analyze", bytes.NewBuffer(payload))
		if err == nil {
			httpReq.Header.Set("Content-Type", "application/json")
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(httpReq)
			if err == nil {
				var result map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&result)
				resp.Body.Close()

				if status, ok := result["status"].(string); ok && status == "BLOCKED" {
					reason := "Unknown reason"
					if r, ok := result["reason"].(string); ok {
						reason = r
					}
					return fmt.Errorf("BLOCKED BY ANTIFRAUD: %v", reason)
				}
			} else {
				log.Printf("Warning: Could not reach antifraud service: %v", err)
			}
		}
	}

	// 3. Execution Phase: Immutable double-entry accounting
	
	// Create Transaction
	var txID string
	err = tx.QueryRow(ctx, "INSERT INTO transactions (idempotency_key, type) VALUES ($1, 'PAYMENT') RETURNING id", req.IdempotencyKey).Scan(&txID)
	if err != nil {
		return fmt.Errorf("transaction might already exist (idempotency): %v", err)
	}

	// Create DEBIT entry (sender)
	_, err = tx.Exec(ctx, "INSERT INTO entries (transaction_id, account_id, direction, amount) VALUES ($1, $2, 'DEBIT', $3)", txID, fromAccountID, req.Amount)
	if err != nil {
		return fmt.Errorf("failed to create debit entry: %v", err)
	}

	// Create CREDIT entry (receiver)
	// First, check if receiver exists
	var toStatus string
	var toCurrency string
	err = tx.QueryRow(ctx, "SELECT status, currency FROM financial_accounts WHERE id = $1 FOR UPDATE", req.ToAccountID).Scan(&toStatus, &toCurrency)
	if err != nil || toStatus == "CLOSED" {
		return fmt.Errorf("recipient account invalid or closed (ID: %s): %v", req.ToAccountID, err)
	}

	creditAmount := req.Amount
	if fromCurrency != toCurrency {
		converted, convErr := convertCurrency(req.Amount, fromCurrency, toCurrency)
		if convErr != nil {
			return fmt.Errorf("currency conversion error: %v", convErr)
		}
		creditAmount = converted
		log.Printf("[CURRENCY CONVERSION] Converted %d %s to %d %s for transaction %s", req.Amount, fromCurrency, creditAmount, toCurrency, req.IdempotencyKey)
	}

	_, err = tx.Exec(ctx, "INSERT INTO entries (transaction_id, account_id, direction, amount) VALUES ($1, $2, 'CREDIT', $3)", txID, req.ToAccountID, creditAmount)
	if err != nil {
		return fmt.Errorf("failed to create credit entry: %v", err)
	}

	return tx.Commit(ctx)
}

func convertCurrency(amount int64, fromCur, toCur string) (int64, error) {
	fromCur = strings.ToUpper(fromCur)
	toCur = strings.ToUpper(toCur)
	if fromCur == toCur {
		return amount, nil
	}

	rates := map[string]float64{
		"CAD": 1.0,
		"USD": 1.37,    // 1 USD = 1.37 CAD
		"EUR": 1.47,    // 1 EUR = 1.47 CAD
		"JPY": 0.0087,  // 1 JPY = 0.0087 CAD
	}

	fromRate, ok1 := rates[fromCur]
	toRate, ok2 := rates[toCur]
	if !ok1 || !ok2 {
		return 0, fmt.Errorf("unsupported currency conversion from %s to %s", fromCur, toCur)
	}

	// Convert to CAD (base)
	amountInBase := float64(amount) * fromRate
	// Convert from CAD to target currency
	convertedAmount := amountInBase / toRate

	// Round to nearest integer (cent/unit)
	return int64(convertedAmount + 0.5), nil
}

