package analyzer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AnalyzeRequest struct {
	Type           string `json:"type"` // "PAYMENT" or "DEPOSIT"
	PayerEmail     string `json:"payer_email"`
	FromAccountID  string `json:"from_account_id"`
	ToAccountID    string `json:"to_account_id"`
	Amount         int64  `json:"amount"`
	ClientIP       string `json:"client_ip"`
}

type AnalyzeResponse struct {
	Status string `json:"status"` // "APPROVED" or "BLOCKED"
	Reason string `json:"reason,omitempty"`
}

type AntifraudAnalyzer struct {
	AccountDB *pgxpool.Pool
	LedgerDB  *pgxpool.Pool
}

func NewAntifraudAnalyzer(accountDB, ledgerDB *pgxpool.Pool) *AntifraudAnalyzer {
	// Create logs table if not exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Create user_ips table in AccountDB
	_, _ = accountDB.Exec(ctx, "CREATE TABLE IF NOT EXISTS user_ips (email TEXT, ip_address TEXT, created_at TIMESTAMP DEFAULT NOW())")
	
	// Create antifraud_logs table in LedgerDB
	createLogsTable := `
		CREATE TABLE IF NOT EXISTS antifraud_logs (
			id SERIAL PRIMARY KEY,
			payer_email TEXT,
			from_account_id TEXT,
			to_account_id TEXT,
			amount BIGINT,
			status TEXT,
			reason TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		)
	`
	_, _ = ledgerDB.Exec(ctx, createLogsTable)

	return &AntifraudAnalyzer{
		AccountDB: accountDB,
		LedgerDB:  ledgerDB,
	}
}

func (a *AntifraudAnalyzer) Analyze(ctx context.Context, req AnalyzeRequest) AnalyzeResponse {
	reason := ""
	status := "APPROVED"

	// Skip analysis if fromAccountID is missing (e.g. some system deposits)
	if req.FromAccountID != "" {
		err := a.executeRules(ctx, req)
		if err != nil {
			status = "BLOCKED"
			reason = err.Error()
		}
	}

	// Log to database
	_, _ = a.LedgerDB.Exec(ctx, 
		"INSERT INTO antifraud_logs (payer_email, from_account_id, to_account_id, amount, status, reason) VALUES ($1, $2, $3, $4, $5, $6)",
		req.PayerEmail, req.FromAccountID, req.ToAccountID, req.Amount, status, reason)

	return AnalyzeResponse{
		Status: status,
		Reason: reason,
	}
}

func (a *AntifraudAnalyzer) executeRules(ctx context.Context, req AnalyzeRequest) error {
	// Layer 5: Honeypots
	if err := a.checkHoneypot(ctx, req); err != nil { return err }

	// Layer 1: Velocity Checks
	if err := a.checkVelocity(ctx, req.FromAccountID); err != nil { return err }

	// Layer 2: Circular Money Flow
	if err := a.checkCircularFlow(ctx, req.FromAccountID, req.ToAccountID); err != nil { return err }

	// Layer 3: Impossible Travel
	if err := a.checkImpossibleTravel(ctx, req); err != nil { return err }

	// Layer 4: Benford's Law
	if err := a.checkBenfordsLaw(ctx, req.FromAccountID); err != nil { return err }

	return nil
}

func (a *AntifraudAnalyzer) checkHoneypot(ctx context.Context, req AnalyzeRequest) error {
	var status string
	err := a.LedgerDB.QueryRow(ctx, "SELECT status FROM financial_accounts WHERE id = $1", req.ToAccountID).Scan(&status)
	if err == nil && status == "HONEYPOT" {
		// Immediately lock the sender's account
		_, _ = a.LedgerDB.Exec(ctx, "UPDATE financial_accounts SET status = 'CLOSED' WHERE id = $1", req.FromAccountID)
		return fmt.Errorf("ANTIFRAUD L5: CRITICAL SECURITY ALERT - Account locked due to HONEYPOT interaction")
	}
	return nil
}

func (a *AntifraudAnalyzer) checkVelocity(ctx context.Context, accountID string) error {
	query := `
		SELECT COUNT(*), COALESCE(SUM(amount), 0)
		FROM entries 
		WHERE account_id = $1 AND direction = 'DEBIT' AND created_at > NOW() - INTERVAL '1 hour'
	`
	var count int
	var sum int64
	if err := a.LedgerDB.QueryRow(ctx, query, accountID).Scan(&count, &sum); err != nil {
		if err != pgx.ErrNoRows {
			// Log error if needed, but don't block
		}
	} else {
		if count > 10 {
			return fmt.Errorf("ANTIFRAUD L1: Velocity limit exceeded (>10 transactions/hour)")
		}
		if sum > 5000000 { // 50,000.00 CAD
			return fmt.Errorf("ANTIFRAUD L1: Volume limit exceeded (>50k/hour)")
		}
	}

	microQuery := `
		SELECT COUNT(*)
		FROM entries
		WHERE account_id = $1 AND direction = 'DEBIT' AND amount < 200 AND created_at > NOW() - INTERVAL '5 minutes'
	`
	var microCount int
	if err := a.LedgerDB.QueryRow(ctx, microQuery, accountID).Scan(&microCount); err == nil {
		if microCount >= 3 {
			return fmt.Errorf("ANTIFRAUD L1: Micro-fraud detected (rapid small transactions)")
		}
	}
	return nil
}

func (a *AntifraudAnalyzer) checkCircularFlow(ctx context.Context, fromAccountID, toAccountID string) error {
	// If the accounts belong to the same owner, it is a transfer between own accounts and not circular money laundering
	var fromOwner, toOwner string
	err1 := a.LedgerDB.QueryRow(ctx, "SELECT owner_id FROM financial_accounts WHERE id = $1", fromAccountID).Scan(&fromOwner)
	err2 := a.LedgerDB.QueryRow(ctx, "SELECT owner_id FROM financial_accounts WHERE id = $1", toAccountID).Scan(&toOwner)
	if err1 == nil && err2 == nil && fromOwner == toOwner {
		return nil
	}

	query := `
		WITH RECURSIVE transfer_graph AS (
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
	err := a.LedgerDB.QueryRow(ctx, query, toAccountID, fromAccountID).Scan(&found)
	if err == nil && found == 1 {
		return fmt.Errorf("ANTIFRAUD L2: Circular money laundering flow detected")
	}
	return nil
}

func (a *AntifraudAnalyzer) checkImpossibleTravel(ctx context.Context, req AnalyzeRequest) error {
	if req.ClientIP == "" || req.PayerEmail == "" {
		return nil
	}

	clientIP := cleanIP(req.ClientIP)
	if isPrivateIP(clientIP) {
		return nil
	}

	query := `
		SELECT ip_address 
		FROM user_ips 
		WHERE email = $1 AND created_at > NOW() - INTERVAL '5 minutes'
		ORDER BY created_at DESC LIMIT 1
	`
	var lastIPRaw string
	err := a.AccountDB.QueryRow(ctx, query, req.PayerEmail).Scan(&lastIPRaw)
	
	_, _ = a.AccountDB.Exec(ctx, "INSERT INTO user_ips (email, ip_address) VALUES ($1, $2)", req.PayerEmail, clientIP)

	if err == nil && lastIPRaw != "" {
		lastIP := cleanIP(lastIPRaw)
		if lastIP != clientIP {
			return fmt.Errorf("ANTIFRAUD L3: Impossible Travel / IP Abnormality detected (IP changed from %s to %s in <5m)", lastIP, clientIP)
		}
	}
	return nil
}

func cleanIP(ipStr string) string {
	if commaIdx := strings.Index(ipStr, ","); commaIdx != -1 {
		ipStr = strings.TrimSpace(ipStr[:commaIdx])
	}
	host, _, err := net.SplitHostPort(ipStr)
	if err == nil {
		return host
	}
	return ipStr
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate()
}

func (a *AntifraudAnalyzer) checkBenfordsLaw(ctx context.Context, accountID string) error {
	query := `
		SELECT CAST(LEFT(CAST(amount AS TEXT), 1) AS INTEGER) AS first_digit, COUNT(*)
		FROM entries
		WHERE account_id = $1 AND direction = 'DEBIT'
		GROUP BY first_digit
	`
	rows, err := a.LedgerDB.Query(ctx, query, accountID)
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

	if totalCount > 20 {
		percentageOfNine := float64(countOfNine) / float64(totalCount)
		if percentageOfNine > 0.25 {
			return fmt.Errorf("ANTIFRAUD L4: Mathematical anomaly (Benford's Law violation - abnormal frequency of digit 9)")
		}
	}
	return nil
}
