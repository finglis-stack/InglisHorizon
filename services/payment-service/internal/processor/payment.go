package processor

import (
	"context"
	"fmt"
	"log"
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

	// 1. Verification Phase: Find the user in Account DB
	var ownerID string
	err = p.AccountDB.QueryRow(ctx, "SELECT id FROM secure_accounts WHERE email = $1", req.PayerEmail).Scan(&ownerID)
	if err != nil {
		return fmt.Errorf("payer account not found in Account DB: %v", err)
	}

	// Anti-Fraud Placeholder: Here we could call an anti-fraud service
	// if err := CallAntiFraudService(req, ownerID); err != nil { return err }

	// 2. Account Phase: Find the payer's account
	var fromAccountID string
	var status string
	var accType string

	if req.FromAccountID != "" {
		fromAccountID = req.FromAccountID
		err = tx.QueryRow(ctx, "SELECT account_type, status FROM financial_accounts WHERE id = $1 AND owner_id = $2 FOR UPDATE", fromAccountID, ownerID).Scan(&accType, &status)
		if err != nil || status == "CLOSED" {
			return fmt.Errorf("provided sender account invalid or closed")
		}
	} else {
		err = tx.QueryRow(ctx, "SELECT id, account_type, status FROM financial_accounts WHERE owner_id = $1 AND account_type = 'DEPOSIT' AND status != 'CLOSED' LIMIT 1 FOR UPDATE", ownerID).Scan(&fromAccountID, &accType, &status)
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
	err = tx.QueryRow(ctx, "SELECT status FROM financial_accounts WHERE id = $1 FOR UPDATE", req.ToAccountID).Scan(&toStatus)
	if err != nil || toStatus == "CLOSED" {
		return fmt.Errorf("recipient account invalid or closed (ID: %s): %v", req.ToAccountID, err)
	}

	_, err = tx.Exec(ctx, "INSERT INTO entries (transaction_id, account_id, direction, amount) VALUES ($1, $2, 'CREDIT', $3)", txID, req.ToAccountID, req.Amount)
	if err != nil {
		return fmt.Errorf("failed to create credit entry: %v", err)
	}

	return tx.Commit(ctx)
}
