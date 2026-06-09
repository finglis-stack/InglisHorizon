package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"account-service/internal/crypto"
	"account-service/internal/models"
	
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JWT Secret Key
var jwtSecretKey = []byte(os.Getenv("PII_MASTER_KEY_B64"))

type AccountRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	SIN      string `json:"sin"`
	Address  string `json:"address"`
	DOB      string `json:"dob"` // Date of birth
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// Middleware to verify JWT and check required roles
func rbacMiddleware(requiredRoles []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"message":"Unauthorized: Missing or invalid token"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, `{"message":"Unauthorized: Invalid token"}`, http.StatusUnauthorized)
			return
		}

		// Check role
		roleMatch := false
		for _, role := range requiredRoles {
			if claims.Role == role {
				roleMatch = true
				break
			}
		}

		if !roleMatch {
			http.Error(w, `{"message":"Forbidden: Insufficient privileges"}`, http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

func main() {
	log.Println("Starting Account Service API...")

	if os.Getenv("PII_MASTER_KEY_B64") == "" {
		log.Println("WARNING: PII_MASTER_KEY_B64 is not set. JWT Secret will be empty.")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer pool.Close()

	if err := models.CreateTable(context.Background(), pool); err != nil {
		log.Fatalf("Failed to create accounts table: %v", err)
	}
	
	if err := models.CreateAdminTableAndSeed(context.Background(), pool); err != nil {
		log.Fatalf("Failed to initialize admin users table: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("POST /admin/login", func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Invalid payload"}`, http.StatusBadRequest)
			return
		}

		admin, err := models.GetAdminByEmail(context.Background(), pool, req.Email)
		if err != nil {
			http.Error(w, `{"message":"Invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		err = models.CompareHashAndPassword(admin.PasswordHash, req.Password)
		if err != nil {
			http.Error(w, `{"message":"Invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		expirationTime := time.Now().Add(12 * time.Hour)
		claims := &Claims{
			Role: admin.Role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Subject:   admin.Email,
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtSecretKey)
		if err != nil {
			http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token": tokenString,
			"role":  admin.Role,
		})
	})

	// Secure route (Only MANAGER can create accounts)
	mux.HandleFunc("POST /admin/accounts", rbacMiddleware([]string{"MANAGER"}, func(w http.ResponseWriter, r *http.Request) {
		var req AccountRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Invalid JSON payload"}`, http.StatusBadRequest)
			return
		}

		if req.Email == "" || req.Name == "" {
			http.Error(w, `{"message":"Missing required fields"}`, http.StatusBadRequest)
			return
		}

		key, err := crypto.GetMasterKey()
		if err != nil {
			log.Printf("Crypto error: %v", err)
			http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
			return
		}

		// Email is NO LONGER encrypted
		encName, _ := crypto.Encrypt(req.Name, key)
		encSIN, _ := crypto.Encrypt(req.SIN, key)
		encAddress, _ := crypto.Encrypt(req.Address, key)
		encDOB, _ := crypto.Encrypt(req.DOB, key)

		query := `
			INSERT INTO secure_accounts (email, encrypted_full_name, encrypted_sin, encrypted_address, encrypted_dob)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id;
		`
		var newID string
		err = pool.QueryRow(context.Background(), query, req.Email, encName, encSIN, encAddress, encDOB).Scan(&newID)
		if err != nil {
			log.Printf("DB error: %v", err)
			http.Error(w, `{"message":"Failed to insert account"}`, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(newID))
	}))

	// Search route (MANAGER or SUPPORT)
	mux.HandleFunc("GET /admin/accounts/search", rbacMiddleware([]string{"MANAGER", "SUPPORT"}, func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		if email == "" {
			http.Error(w, `{"message":"Email query parameter is required"}`, http.StatusBadRequest)
			return
		}

		var acc models.Account
		query := `SELECT id, email, encrypted_full_name, encrypted_sin, encrypted_address, encrypted_dob FROM secure_accounts WHERE email = $1`
		err := pool.QueryRow(context.Background(), query, email).Scan(&acc.ID, &acc.Email, &acc.EncryptedFullName, &acc.EncryptedSIN, &acc.EncryptedAddress, &acc.EncryptedDOB)
		if err != nil {
			http.Error(w, `{"message":"Account not found"}`, http.StatusNotFound)
			return
		}

		key, err := crypto.GetMasterKey()
		if err != nil {
			http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
			return
		}

		// Decrypt in memory
		acc.FullName, _ = crypto.Decrypt(acc.EncryptedFullName, key)
		acc.SIN, _ = crypto.Decrypt(acc.EncryptedSIN, key)
		acc.Address, _ = crypto.Decrypt(acc.EncryptedAddress, key)
		acc.DOB, _ = crypto.Decrypt(acc.EncryptedDOB, key)

		// Don't send encrypted strings back to client
		acc.EncryptedFullName = ""
		acc.EncryptedSIN = ""
		acc.EncryptedAddress = ""
		acc.EncryptedDOB = ""

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acc)
	}))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Account Service running on port %s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
