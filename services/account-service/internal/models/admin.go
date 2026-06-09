package models

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/pbkdf2"
)

type AdminUser struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
}

const (
	pbkdf2Iterations = 250000
	saltLength       = 16
	keyLength        = 32
)

// HashPassword generates a PBKDF2 hash using a random salt.
// Returns a string in the format "hexSalt:hexHash".
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, keyLength, sha256.New)
	
	return fmt.Sprintf("%x:%x", salt, hash), nil
}

// CompareHashAndPassword verifies a password against a "hexSalt:hexHash" string.
func CompareHashAndPassword(storedHash, password string) error {
	parts := strings.Split(storedHash, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid hash format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return err
	}

	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return err
	}

	hash := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, keyLength, sha256.New)

	if subtle.ConstantTimeCompare(hash, expectedHash) != 1 {
		return fmt.Errorf("password mismatch")
	}

	return nil
}

func CreateAdminTableAndSeed(ctx context.Context, db *pgxpool.Pool) error {
	query := `
	CREATE TABLE IF NOT EXISTS admin_users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL
	);`
	
	_, err := db.Exec(ctx, query)
	if err != nil {
		return err
	}

	// Check if the master admin exists
	var count int
	err = db.QueryRow(ctx, "SELECT COUNT(*) FROM admin_users").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		email := os.Getenv("INITIAL_ADMIN_EMAIL")
		password := os.Getenv("INITIAL_ADMIN_PASSWORD")

		if email == "" || password == "" {
			log.Println("WARNING: Database is empty but INITIAL_ADMIN_EMAIL or INITIAL_ADMIN_PASSWORD is not set. Skipping master admin seeding.")
			return nil
		}

		log.Println("Database is empty. Seeding the initial Master Admin with PBKDF2-250k...")
		role := "MANAGER"

		hashStr, err := HashPassword(password)
		if err != nil {
			return err
		}

		insertQuery := `INSERT INTO admin_users (email, password_hash, role) VALUES ($1, $2, $3)`
		_, err = db.Exec(ctx, insertQuery, email, hashStr, role)
		if err != nil {
			return err
		}
		log.Println("Master Admin seeded successfully.")
	}

	return nil
}

func GetAdminByEmail(ctx context.Context, db *pgxpool.Pool, email string) (*AdminUser, error) {
	var admin AdminUser
	query := `SELECT id, email, password_hash, role FROM admin_users WHERE email = $1`
	err := db.QueryRow(ctx, query, email).Scan(&admin.ID, &admin.Email, &admin.PasswordHash, &admin.Role)
	if err != nil {
		return nil, err
	}
	return &admin, nil
}
