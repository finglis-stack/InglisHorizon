package models

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Account struct {
	ID          string  `json:"id"`
	OwnerID     string  `json:"owner_id"`
	Currency    string  `json:"currency"`
	Type        string  `json:"account_type"`
	Status      string  `json:"status"`
	APR         float64 `json:"apr"`
	CreditLimit int64   `json:"credit_limit"`
}

type Transaction struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Direction string    `json:"direction"`
	Amount    int64     `json:"amount"`
	CreatedAt time.Time `json:"created_at"`
}

// InitDB creates the strict financial ledger tables.
func InitDB(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	-- Accounts table (Holds rules, NOT balances)
	CREATE TABLE IF NOT EXISTS financial_accounts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		owner_id UUID NOT NULL,
		currency VARCHAR(3) NOT NULL,
		account_type TEXT NOT NULL, -- 'DEPOSIT' or 'CREDIT'
		interest_rate_apr NUMERIC(5,2) DEFAULT 0.00,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	-- Transactions table (The event)
	CREATE TABLE IF NOT EXISTS transactions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		idempotency_key TEXT UNIQUE NOT NULL,
		type TEXT NOT NULL, -- 'TRANSFER', 'INTEREST_CHARGE', 'DEPOSIT'
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	-- Entries table (Double Entry Accounting)
	CREATE TABLE IF NOT EXISTS entries (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		transaction_id UUID NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
		account_id UUID NOT NULL REFERENCES financial_accounts(id),
		direction TEXT NOT NULL, -- 'CREDIT' or 'DEBIT'
		amount BIGINT NOT NULL CHECK (amount > 0),
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	-- Index for fast balance calculation
	CREATE INDEX IF NOT EXISTS idx_entries_account_id ON entries(account_id);
	`
	_, err := db.Exec(ctx, query)
	if err != nil {
		log.Printf("Failed to initialize ledger tables: %v", err)
		return err
	}

	// Migrate existing tables to add status if not exists
	alterQuery := `ALTER TABLE financial_accounts ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE';`
	_, err = db.Exec(ctx, alterQuery)
	if err != nil {
		log.Printf("Failed to add status column: %v", err)
	}

	// Migrate existing tables to add credit_limit if not exists
	alterQueryLimit := `ALTER TABLE financial_accounts ADD COLUMN IF NOT EXISTS credit_limit BIGINT NOT NULL DEFAULT 0;`
	_, err = db.Exec(ctx, alterQueryLimit)
	if err != nil {
		log.Printf("Failed to add credit_limit column: %v", err)
	}

	return err
}

// CreateAccount creates a new financial account.
func CreateAccount(ctx context.Context, db *pgxpool.Pool, ownerID string, currency string, accType string, apr float64, creditLimit int64) (string, error) {
	var newID string
	query := `INSERT INTO financial_accounts (owner_id, currency, account_type, interest_rate_apr, credit_limit) 
			  VALUES ($1, $2, $3, $4, $5) RETURNING id`
	err := db.QueryRow(ctx, query, ownerID, currency, accType, apr, creditLimit).Scan(&newID)
	return newID, err
}

// GetAccount retrieves metadata for a single financial account.
func GetAccount(ctx context.Context, db *pgxpool.Pool, accountID string) (*Account, error) {
	var a Account
	query := `SELECT id, owner_id, currency, account_type, status, interest_rate_apr, credit_limit FROM financial_accounts WHERE id = $1`
	err := db.QueryRow(ctx, query, accountID).Scan(&a.ID, &a.OwnerID, &a.Currency, &a.Type, &a.Status, &a.APR, &a.CreditLimit)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetAccountsByOwner retrieves all financial accounts for a given client.
func GetAccountsByOwner(ctx context.Context, db *pgxpool.Pool, ownerID string) ([]Account, error) {
	query := `SELECT id, owner_id, currency, account_type, status, interest_rate_apr, credit_limit FROM financial_accounts WHERE owner_id = $1 ORDER BY created_at DESC`
	rows, err := db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.OwnerID, &a.Currency, &a.Type, &a.Status, &a.APR, &a.CreditLimit); err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, nil
}

// CloseAccount marks an account as 'CLOSED' instead of deleting it.
func CloseAccount(ctx context.Context, db *pgxpool.Pool, accountID string) error {
	query := `UPDATE financial_accounts SET status = 'CLOSED' WHERE id = $1 AND status != 'CLOSED'`
	tag, err := db.Exec(ctx, query, accountID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("account not found or already closed")
	}
	return nil
}

// GetBalance calculates the balance dynamically based on all entries.
func GetBalance(ctx context.Context, db *pgxpool.Pool, accountID string) (int64, error) {
	query := `
		SELECT 
			COALESCE(SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END), 0) -
			COALESCE(SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END), 0)
		FROM entries
		WHERE account_id = $1
	`
	var balance int64
	err := db.QueryRow(ctx, query, accountID).Scan(&balance)
	return balance, err
}

// GetTransactions retrieves paginated transaction history for a given account.
func GetTransactions(ctx context.Context, db *pgxpool.Pool, accountID string, limit, offset int) ([]Transaction, error) {
	query := `
		SELECT t.id, t.type, e.direction, e.amount, e.created_at
		FROM entries e
		JOIN transactions t ON e.transaction_id = t.id
		WHERE e.account_id = $1
		ORDER BY e.created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := db.Query(ctx, query, accountID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var txs []Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(&tx.ID, &tx.Type, &tx.Direction, &tx.Amount, &tx.CreatedAt); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

// Transfer atomically moves funds between two accounts.
func Transfer(ctx context.Context, db *pgxpool.Pool, fromAccountID, toAccountID string, amount int64, idempotencyKey string) error {
	if amount <= 0 {
		return fmt.Errorf("amount must be greater than zero")
	}

	// Begin atomic transaction
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// 0. Check if sender account is active and has sufficient balance for DEPOSIT accounts
	var accType, accStatus string
	var creditLimit int64
	err = tx.QueryRow(ctx, "SELECT account_type, status, credit_limit FROM financial_accounts WHERE id = $1 FOR UPDATE", fromAccountID).Scan(&accType, &accStatus, &creditLimit)
	if err != nil {
		return fmt.Errorf("sender account not found")
	}
	if accStatus == "CLOSED" {
		return fmt.Errorf("sender account is closed")
	}

	// For DEPOSIT accounts, verify sufficient balance
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
			return fmt.Errorf("failed to check balance")
		}
		if balance < amount {
			return fmt.Errorf("insufficient funds")
		}
	} else if accType == "CREDIT" {
		var balance int64
		balQuery := `
			SELECT 
				COALESCE(SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END), 0) -
				COALESCE(SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END), 0)
			FROM entries WHERE account_id = $1
		`
		err = tx.QueryRow(ctx, balQuery, fromAccountID).Scan(&balance)
		if err != nil {
			return fmt.Errorf("failed to check balance")
		}
		if balance-amount < -creditLimit {
			return fmt.Errorf("transaction rejects: credit limit exceeded")
		}
	}

	// 1. Create Transaction record
	var txID string
	err = tx.QueryRow(ctx, "INSERT INTO transactions (idempotency_key, type) VALUES ($1, 'TRANSFER') RETURNING id", idempotencyKey).Scan(&txID)
	if err != nil {
		return fmt.Errorf("idempotency key might already exist: %v", err)
	}

	// 2. Create DEBIT entry (sender)
	_, err = tx.Exec(ctx, "INSERT INTO entries (transaction_id, account_id, direction, amount) VALUES ($1, $2, 'DEBIT', $3)", txID, fromAccountID, amount)
	if err != nil {
		return err
	}

	// 3. Create CREDIT entry (receiver)
	_, err = tx.Exec(ctx, "INSERT INTO entries (transaction_id, account_id, direction, amount) VALUES ($1, $2, 'CREDIT', $3)", txID, toAccountID, amount)
	if err != nil {
		return err
	}

	// Commit transaction
	return tx.Commit(ctx)
}

// AccrueDailyInterest calculates daily interest for all CREDIT accounts and adds an entry.
func AccrueDailyInterest(ctx context.Context, db *pgxpool.Pool, batchID string) error {
	// For each CREDIT account, get balance, calculate interest, and insert.
	// This is a simplified approach. In a real 850k system, this would be paginated.
	
	query := `SELECT id, interest_rate_apr FROM financial_accounts WHERE account_type = 'CREDIT'`
	rows, err := db.Query(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var accountID string
		var apr float64
		if err := rows.Scan(&accountID, &apr); err != nil {
			log.Printf("Error scanning account: %v", err)
			continue
		}

		if apr <= 0 {
			continue
		}

		// 1. Fetch total credits (payments/refunds)
		var totalCredits int64
		err = db.QueryRow(ctx, "SELECT COALESCE(SUM(amount), 0) FROM entries WHERE account_id = $1 AND direction = 'CREDIT'", accountID).Scan(&totalCredits)
		if err != nil {
			log.Printf("Error getting credits for account %s: %v", accountID, err)
			continue
		}

		// 2. Fetch all debits (purchases) that are NOT interest charges to prevent interest compounding
		debitQuery := `
			SELECT e.amount, e.created_at 
			FROM entries e 
			JOIN transactions t ON e.transaction_id = t.id 
			WHERE e.account_id = $1 AND e.direction = 'DEBIT' AND t.type != 'INTEREST_CHARGE'
			ORDER BY e.created_at ASC
		`
		debitRows, err := db.Query(ctx, debitQuery, accountID)
		if err != nil {
			log.Printf("Error querying debits for account %s: %v", accountID, err)
			continue
		}
		
		type debitItem struct {
			amount    int64
			createdAt time.Time
		}
		var debits []debitItem
		for debitRows.Next() {
			var d debitItem
			if err := debitRows.Scan(&d.amount, &d.createdAt); err == nil {
				debits = append(debits, d)
			}
		}
		debitRows.Close()

		// 3. FIFO match credits against debits to find unpaid debits older than 21 days (grace period)
		var interestBase int64 = 0
		now := time.Now()
		for _, debit := range debits {
			unpaidAmount := debit.amount
			if totalCredits >= unpaidAmount {
				totalCredits -= unpaidAmount
				unpaidAmount = 0
			} else if totalCredits > 0 {
				unpaidAmount -= totalCredits
				totalCredits = 0
			}

			if unpaidAmount > 0 {
				// Only charge interest if the purchase was made > 21 days ago
				if now.Sub(debit.createdAt) > 21*24*time.Hour {
					interestBase += unpaidAmount
				}
			}
		}

		if interestBase <= 0 {
			continue
		}

		// Calculate daily interest on interestBase (simple interest, not compounded)
		dailyInterest := int64((float64(interestBase) * (apr / 100.0)) / 365.0)

		if dailyInterest <= 0 {
			continue
		}

		// Add interest charge transaction
		idempotencyKey := fmt.Sprintf("interest_%s_%s", batchID, accountID)
		
		tx, err := db.Begin(ctx)
		if err != nil {
			continue
		}
		
		var txID string
		err = tx.QueryRow(ctx, "INSERT INTO transactions (idempotency_key, type) VALUES ($1, 'INTEREST_CHARGE') RETURNING id", idempotencyKey).Scan(&txID)
		if err == nil {
			// Interest charge DEBITs the account (increases the owed amount)
			_, _ = tx.Exec(ctx, "INSERT INTO entries (transaction_id, account_id, direction, amount) VALUES ($1, $2, 'DEBIT', $3)", txID, accountID, dailyInterest)
			tx.Commit(ctx)
		} else {
			tx.Rollback(ctx)
		}
	}
	return nil
}
