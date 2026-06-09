package models

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Account represents a user's PII profile in the secure database.
type Account struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Email string `json:"email"`

	// These fields are stored as ciphertext in PostgreSQL
	EncryptedFullName string `json:"-"`
	EncryptedSIN      string `json:"-"` // Social Insurance Number (NAS)
	EncryptedAddress  string `json:"-"`
	EncryptedDOB      string `json:"-"`

	// Cleartext properties for application usage
	FullName string `json:"full_name"`
	SIN      string `json:"sin,omitempty"`
	Address  string `json:"address,omitempty"`
	DOB      string `json:"dob,omitempty"`
}

// CreateTable initializes the secure accounts table in PostgreSQL
func CreateTable(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	CREATE TABLE IF NOT EXISTS secure_accounts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		email TEXT UNIQUE NOT NULL,
		encrypted_full_name TEXT NOT NULL,
		encrypted_sin TEXT,
		encrypted_address TEXT,
		encrypted_dob TEXT
	);`
	_, err := db.Exec(ctx, query)
	return err
}
