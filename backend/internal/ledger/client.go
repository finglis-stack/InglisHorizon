package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// CreateMerchantAccounts provisions CAD, USD, EUR, and JPY deposit accounts for the merchant in the ledger service.
func CreateMerchantAccounts(ctx context.Context, merchantID string) error {
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	if jwtSecret == "" {
		return fmt.Errorf("JWT_SECRET_KEY environment variable is not set")
	}

	// Generate JWT token with MANAGER role
	tokenClaims := &Claims{
		Role: "MANAGER",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "merchant-service-internal",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return fmt.Errorf("failed to sign JWT token: %w", err)
	}

	// Determine Ledger Service URL
	ledgerURL := os.Getenv("LEDGER_SERVICE_URL")
	if ledgerURL == "" {
		// Fallback to internal Railway DNS
		ledgerURL = "http://ledger-service.railway.internal:8483"
	}

	currencies := []string{"CAD", "USD", "EUR", "JPY"}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, cur := range currencies {
		payload := map[string]interface{}{
			"owner_id":     merchantID,
			"currency":     cur,
			"account_type": "DEPOSIT",
			"apr":          0.0,
		}

		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal request payload: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", ledgerURL+"/ledger/accounts", bytes.NewBuffer(bodyBytes))
		if err != nil {
			return fmt.Errorf("failed to create http request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokenString)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[LEDGER CLIENT] Failed to create %s account for merchant %s: %v", cur, merchantID, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			log.Printf("[LEDGER CLIENT] Failed to create %s account, status code: %d", cur, resp.StatusCode)
			continue
		}

		log.Printf("[LEDGER CLIENT] Successfully created %s account for merchant %s", cur, merchantID)
	}

	return nil
}
