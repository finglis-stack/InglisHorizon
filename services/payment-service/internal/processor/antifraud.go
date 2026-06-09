package processor

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckAntiFraud executes the 5 layers of the anti-fraud system.
func (p *PaymentProcessor) CheckAntiFraud(ctx context.Context, tx pgx.Tx, req PaymentRequest, fromAccountID string) error {
	// Layer 5: Honeypots
	if err := checkHoneypot(ctx, tx, req, fromAccountID); err != nil {
		return err
	}

	// Layer 1: Velocity Checks & Micro-fraud
	if err := checkVelocity(ctx, tx, fromAccountID); err != nil {
		return err
	}

	// Layer 2: Circular Money Flow
	if err := checkCircularFlow(ctx, tx, fromAccountID, req.ToAccountID); err != nil {
		return err
	}

	// Layer 3: Impossible Travel (IP Reputation)
	if err := checkImpossibleTravel(ctx, p.AccountDB, req); err != nil {
		return err
	}

	// Layer 4: Benford's Law
	if err := checkBenfordsLaw(ctx, tx, fromAccountID); err != nil {
		return err
	}

	return nil
}

func checkHoneypot(ctx context.Context, tx pgx.Tx, req PaymentRequest, fromAccountID string) error {
	var status string
	err := tx.QueryRow(ctx, "SELECT status FROM financial_accounts WHERE id = $1", req.ToAccountID).Scan(&status)
	if err == nil && status == "HONEYPOT" {
		// Immediately lock the sender's account
		_, _ = tx.Exec(ctx, "UPDATE financial_accounts SET status = 'CLOSED' WHERE id = $1", fromAccountID)
		return fmt.Errorf("ANTIFRAUD L5: CRITICAL SECURITY ALERT - Account locked due to HONEYPOT interaction")
	}
	return nil
}

func checkVelocity(ctx context.Context, tx pgx.Tx, accountID string) error {
	// Query transactions in the last 1 hour
	query := `
		SELECT COUNT(*), COALESCE(SUM(amount), 0)
		FROM entries 
		WHERE account_id = $1 AND direction = 'DEBIT' AND created_at > NOW() - INTERVAL '1 hour'
	`
	var count int
	var sum int64
	if err := tx.QueryRow(ctx, query, accountID).Scan(&count, &sum); err != nil {
		return err
	}
	
	if count > 10 {
		return fmt.Errorf("ANTIFRAUD L1: Velocity limit exceeded (>10 transactions/hour)")
	}
	if sum > 5000000 { // 50,000.00 CAD
		return fmt.Errorf("ANTIFRAUD L1: Volume limit exceeded (>50k/hour)")
	}

	// Micro-fraud check: 3 transactions < $2.00 in the last 5 minutes
	microQuery := `
		SELECT COUNT(*)
		FROM entries
		WHERE account_id = $1 AND direction = 'DEBIT' AND amount < 200 AND created_at > NOW() - INTERVAL '5 minutes'
	`
	var microCount int
	if err := tx.QueryRow(ctx, microQuery, accountID).Scan(&microCount); err == nil {
		if microCount >= 3 {
			return fmt.Errorf("ANTIFRAUD L1: Micro-fraud detected (rapid small transactions)")
		}
	}
	
	return nil
}

func checkCircularFlow(ctx context.Context, tx pgx.Tx, fromAccountID, toAccountID string) error {
	// A simple CTE to find if toAccountID has sent money back to fromAccountID through at most 1 intermediary
	// in the last 24 hours.
	query := `
		WITH RECURSIVE transfer_graph AS (
			-- Base case: direct transfers from toAccountID
			SELECT 
				e1.account_id AS sender, 
				e2.account_id AS receiver, 
				1 AS depth
			FROM entries e1
			JOIN entries e2 ON e1.transaction_id = e2.transaction_id
			WHERE e1.direction = 'DEBIT' AND e2.direction = 'CREDIT' 
			  AND e1.account_id = $1
			  AND e1.created_at > NOW() - INTERVAL '24 hours'
			
			UNION ALL
			
			-- Recursive step
			SELECT 
				tg.sender, 
				e2.account_id AS receiver, 
				tg.depth + 1
			FROM transfer_graph tg
			JOIN entries e1 ON tg.receiver = e1.account_id
			JOIN entries e2 ON e1.transaction_id = e2.transaction_id
			WHERE e1.direction = 'DEBIT' AND e2.direction = 'CREDIT'
			  AND e1.created_at > NOW() - INTERVAL '24 hours'
			  AND tg.depth < 2
		)
		SELECT 1 FROM transfer_graph WHERE receiver = $2 LIMIT 1
	`
	var found int
	err := tx.QueryRow(ctx, query, toAccountID, fromAccountID).Scan(&found)
	if err == nil && found == 1 {
		return fmt.Errorf("ANTIFRAUD L2: Circular money laundering flow detected")
	}
	return nil
}

func checkImpossibleTravel(ctx context.Context, accountDB *pgxpool.Pool, req PaymentRequest) error {
	if req.ClientIP == "" || req.PayerEmail == "" {
		return nil
	}

	query := `
		SELECT ip_address 
		FROM user_ips 
		WHERE email = $1 AND created_at > NOW() - INTERVAL '5 minutes'
		ORDER BY created_at DESC LIMIT 1
	`
	var lastIP string
	err := accountDB.QueryRow(ctx, query, req.PayerEmail).Scan(&lastIP)
	
	_, _ = accountDB.Exec(ctx, "CREATE TABLE IF NOT EXISTS user_ips (email TEXT, ip_address TEXT, created_at TIMESTAMP DEFAULT NOW())")
	_, _ = accountDB.Exec(ctx, "INSERT INTO user_ips (email, ip_address) VALUES ($1, $2)", req.PayerEmail, req.ClientIP)

	if err == nil && lastIP != "" && lastIP != req.ClientIP {
		return fmt.Errorf("ANTIFRAUD L3: Impossible Travel / IP Abnormality detected (IP changed from %s to %s in <5m)", lastIP, req.ClientIP)
	}

	return nil
}

func checkBenfordsLaw(ctx context.Context, tx pgx.Tx, accountID string) error {
	// Extract the first digit of transaction amounts for this user
	query := `
		SELECT CAST(LEFT(CAST(amount AS TEXT), 1) AS INTEGER) AS first_digit, COUNT(*)
		FROM entries
		WHERE account_id = $1 AND direction = 'DEBIT'
		GROUP BY first_digit
	`
	rows, err := tx.Query(ctx, query, accountID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	totalCount := 0
	countOfNine := 0

	for rows.Next() {
		var digit, count int
		if err := rows.Scan(&digit, &count); err != nil {
			continue
		}
		totalCount += count
		if digit == 9 {
			countOfNine = count
		}
	}

	// Benford's Law says 9 should appear ~4.6% of the time.
	// If sample size is > 20 and 9 appears > 25% of the time, flag it.
	if totalCount > 20 {
		percentageOfNine := float64(countOfNine) / float64(totalCount)
		if percentageOfNine > 0.25 {
			return fmt.Errorf("ANTIFRAUD L4: Mathematical anomaly (Benford's Law violation - abnormal frequency of digit 9)")
		}
	}

	return nil
}
