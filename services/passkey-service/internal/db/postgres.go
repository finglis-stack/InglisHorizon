package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	Pool *pgxpool.Pool
}

func Connect() (*DB, error) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is not set")
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing database URL: %w", err)
	}

	config.MaxConns = 20
	config.MinConns = 2
	config.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("error connecting to postgres: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("error pinging postgres: %w", err)
	}

	log.Println("Connected to ledger database for Passkey Service")

	db := &DB{Pool: pool}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("error running migrations: %w", err)
	}

	return db, nil
}

func (db *DB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

func (db *DB) migrate() error {
	ctx := context.Background()

	// 1. Passkey tokens table for dynamic links
	tokenTableQuery := `
	CREATE TABLE IF NOT EXISTS passkey_tokens (
		token UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL REFERENCES financial_accounts(id) ON DELETE CASCADE,
		challenge TEXT NOT NULL,
		user_id BYTEA NOT NULL,
		used BOOLEAN DEFAULT FALSE,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);
	`
	_, err := db.Pool.Exec(ctx, tokenTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create passkey_tokens table: %w", err)
	}

	// 2. Account passkeys table for registered credentials
	passkeyTableQuery := `
	CREATE TABLE IF NOT EXISTS account_passkeys (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL REFERENCES financial_accounts(id) ON DELETE CASCADE,
		credential_id BYTEA UNIQUE NOT NULL,
		public_key BYTEA NOT NULL,
		attestation_type TEXT NOT NULL,
		aaguid BYTEA NOT NULL,
		sign_counter BIGINT NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);
	`
	_, err = db.Pool.Exec(ctx, passkeyTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create account_passkeys table: %w", err)
	}

	// 3. Passkey login sessions table for assertion challenge tracking
	loginSessionTableQuery := `
	CREATE TABLE IF NOT EXISTS passkey_login_sessions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL REFERENCES financial_accounts(id) ON DELETE CASCADE,
		challenge TEXT NOT NULL,
		user_id BYTEA NOT NULL,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);
	`
	_, err = db.Pool.Exec(ctx, loginSessionTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create passkey_login_sessions table: %w", err)
	}

	log.Println("Database migrations executed successfully")
	return nil
}
