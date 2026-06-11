package models

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"inglishorizon-backend/internal/crypto"
)

type Merchant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Address   string    `json:"address"`
	NEQ       string    `json:"neq"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	EncryptedName    string `json:"-"`
	EncryptedAddress string `json:"-"`
	EncryptedNEQ     string `json:"-"`
}

func InitDB(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	CREATE TABLE IF NOT EXISTS merchants (
		id UUID PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		encrypted_name TEXT NOT NULL DEFAULT '',
		encrypted_address TEXT NOT NULL DEFAULT '',
		encrypted_neq TEXT UNIQUE NOT NULL DEFAULT '',
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);`
	_, err := db.Exec(ctx, query)
	if err != nil {
		log.Printf("Failed to initialize merchants table: %v", err)
		return err
	}

	// Migrations for existing tables if columns were in cleartext
	alterQueries := []string{
		`ALTER TABLE merchants ADD COLUMN IF NOT EXISTS encrypted_name TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE merchants ADD COLUMN IF NOT EXISTS encrypted_address TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE merchants ADD COLUMN IF NOT EXISTS encrypted_neq TEXT UNIQUE NOT NULL DEFAULT '';`,
		`ALTER TABLE merchants DROP COLUMN IF EXISTS name;`,
		`ALTER TABLE merchants DROP COLUMN IF EXISTS address;`,
		`ALTER TABLE merchants DROP COLUMN IF EXISTS neq;`,
	}
	for _, q := range alterQueries {
		_, _ = db.Exec(ctx, q)
	}

	return nil
}

func CreateMerchant(ctx context.Context, db *pgxpool.Pool, m *Merchant) error {
	key, err := crypto.GetMasterKey()
	if err != nil {
		return err
	}

	encName, err := crypto.Encrypt(m.Name, key)
	if err != nil {
		return err
	}
	encAddress, err := crypto.Encrypt(m.Address, key)
	if err != nil {
		return err
	}
	encNEQ, err := crypto.Encrypt(m.NEQ, key)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO merchants (id, email, encrypted_name, encrypted_address, encrypted_neq, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING created_at, updated_at;
	`
	return db.QueryRow(ctx, query, m.ID, m.Email, encName, encAddress, encNEQ).Scan(&m.CreatedAt, &m.UpdatedAt)
}

func GetMerchant(ctx context.Context, db *pgxpool.Pool, id string) (*Merchant, error) {
	key, err := crypto.GetMasterKey()
	if err != nil {
		return nil, err
	}

	var m Merchant
	query := `SELECT id, email, encrypted_name, encrypted_address, encrypted_neq, created_at, updated_at FROM merchants WHERE id = $1`
	err = db.QueryRow(ctx, query, id).Scan(&m.ID, &m.Email, &m.EncryptedName, &m.EncryptedAddress, &m.EncryptedNEQ, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}

	m.Name, _ = crypto.Decrypt(m.EncryptedName, key)
	m.Address, _ = crypto.Decrypt(m.EncryptedAddress, key)
	m.NEQ, _ = crypto.Decrypt(m.EncryptedNEQ, key)

	m.EncryptedName = ""
	m.EncryptedAddress = ""
	m.EncryptedNEQ = ""

	return &m, nil
}

func GetMerchantByEmail(ctx context.Context, db *pgxpool.Pool, email string) (*Merchant, error) {
	key, err := crypto.GetMasterKey()
	if err != nil {
		return nil, err
	}

	var m Merchant
	query := `SELECT id, email, encrypted_name, encrypted_address, encrypted_neq, created_at, updated_at FROM merchants WHERE email = $1`
	err = db.QueryRow(ctx, query, email).Scan(&m.ID, &m.Email, &m.EncryptedName, &m.EncryptedAddress, &m.EncryptedNEQ, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}

	m.Name, _ = crypto.Decrypt(m.EncryptedName, key)
	m.Address, _ = crypto.Decrypt(m.EncryptedAddress, key)
	m.NEQ, _ = crypto.Decrypt(m.EncryptedNEQ, key)

	m.EncryptedName = ""
	m.EncryptedAddress = ""
	m.EncryptedNEQ = ""

	return &m, nil
}

func ListMerchants(ctx context.Context, db *pgxpool.Pool) ([]Merchant, error) {
	key, err := crypto.GetMasterKey()
	if err != nil {
		return nil, err
	}

	query := `SELECT id, email, encrypted_name, encrypted_address, encrypted_neq, created_at, updated_at FROM merchants ORDER BY created_at DESC`
	rows, err := db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Merchant
	for rows.Next() {
		var m Merchant
		if err := rows.Scan(&m.ID, &m.Email, &m.EncryptedName, &m.EncryptedAddress, &m.EncryptedNEQ, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		m.Name, _ = crypto.Decrypt(m.EncryptedName, key)
		m.Address, _ = crypto.Decrypt(m.EncryptedAddress, key)
		m.NEQ, _ = crypto.Decrypt(m.EncryptedNEQ, key)

		m.EncryptedName = ""
		m.EncryptedAddress = ""
		m.EncryptedNEQ = ""

		list = append(list, m)
	}
	return list, nil
}

func UpdateMerchant(ctx context.Context, db *pgxpool.Pool, m *Merchant) error {
	key, err := crypto.GetMasterKey()
	if err != nil {
		return err
	}

	encName, err := crypto.Encrypt(m.Name, key)
	if err != nil {
		return err
	}
	encAddress, err := crypto.Encrypt(m.Address, key)
	if err != nil {
		return err
	}
	encNEQ, err := crypto.Encrypt(m.NEQ, key)
	if err != nil {
		return err
	}

	query := `
		UPDATE merchants
		SET email = $1, encrypted_name = $2, encrypted_address = $3, encrypted_neq = $4, updated_at = NOW()
		WHERE id = $5
		RETURNING updated_at;
	`
	return db.QueryRow(ctx, query, m.Email, encName, encAddress, encNEQ, m.ID).Scan(&m.UpdatedAt)
}

func DeleteMerchant(ctx context.Context, db *pgxpool.Pool, id string) error {
	query := `DELETE FROM merchants WHERE id = $1`
	_, err := db.Exec(ctx, query, id)
	return err
}
