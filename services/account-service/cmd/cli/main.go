package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"account-service/internal/crypto"
	"account-service/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	fmt.Println("--- InglisHorizon AMF/Loi25 Admin CLI ---")

	emailPtr := flag.String("email", "", "User's email address")
	namePtr := flag.String("name", "", "User's full name")
	sinPtr := flag.String("sin", "", "User's Social Insurance Number (NAS)")
	addressPtr := flag.String("address", "", "User's residential address")
	kycLevelPtr := flag.Int("kyc", 1, "KYC Level (1-3)")
	consentPtr := flag.Bool("consent", false, "Has explicitly consented to Loi 25 terms")
	
	flag.Parse()

	if *emailPtr == "" || *namePtr == "" {
		log.Fatal("Error: --email and --name are required parameters.")
	}
	if !*consentPtr {
		log.Fatal("Error: Cannot create account without explicit Loi 25 consent (--consent=true).")
	}

	// 1. Get Master Key
	key, err := crypto.GetMasterKey()
	if err != nil {
		log.Fatalf("Security Error: Failed to load master key: %v", err)
	}

	// 2. Encrypt PII
	encEmail, err := crypto.Encrypt(*emailPtr, key)
	if err != nil { log.Fatalf("Failed to encrypt email: %v", err) }
	
	encName, err := crypto.Encrypt(*namePtr, key)
	if err != nil { log.Fatalf("Failed to encrypt name: %v", err) }
	
	encSIN, _ := crypto.Encrypt(*sinPtr, key)
	encAddress, _ := crypto.Encrypt(*addressPtr, key)

	// 3. Connect to DB
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("Error: DATABASE_URL environment variable is not set")
	}

	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}
	defer pool.Close()

	// Ensure table exists
	if err := models.CreateTable(context.Background(), pool); err != nil {
		log.Fatalf("Failed to verify/create table: %v", err)
	}

	// 4. Insert into secure DB
	query := `
		INSERT INTO secure_accounts (encrypted_email, encrypted_full_name, encrypted_sin, encrypted_address, kyc_level, consent_loi25)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id;
	`
	var newID string
	err = pool.QueryRow(context.Background(), query, encEmail, encName, encSIN, encAddress, *kycLevelPtr, *consentPtr).Scan(&newID)
	if err != nil {
		log.Fatalf("Failed to create user in DB: %v", err)
	}

	fmt.Printf("\nSUCCESS: Secure Account Created!\n")
	fmt.Printf("Account UUID: %s\n", newID)
	fmt.Printf("Notice: PII data was encrypted with AES-256-GCM before storage.\n")
}
