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

	log.Println("Connected to portal-db database")

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

	// 1. end_users table
	usersTableQuery := `
	CREATE TABLE IF NOT EXISTS end_users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);
	`
	_, err := db.Pool.Exec(ctx, usersTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create end_users table: %w", err)
	}

	// 2. portal_link_sessions table (tracks pending linking processes)
	sessionsTableQuery := `
	CREATE TABLE IF NOT EXISTS portal_link_sessions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES end_users(id) ON DELETE CASCADE,
		account_id UUID NOT NULL,
		verified BOOLEAN DEFAULT FALSE,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);
	`
	_, err = db.Pool.Exec(ctx, sessionsTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create portal_link_sessions table: %w", err)
	}

	// 3. user_linked_accounts table (final association between end_users and bank ledger accounts)
	linkedAccountsTableQuery := `
	CREATE TABLE IF NOT EXISTS user_linked_accounts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES end_users(id) ON DELETE CASCADE,
		account_id UUID NOT NULL,
		linked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		UNIQUE(user_id, account_id)
	);
	`
	_, err = db.Pool.Exec(ctx, linkedAccountsTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create user_linked_accounts table: %w", err)
	}

	log.Println("Portal database migrations executed successfully")
	return nil
}
