package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"account-service/internal/crypto"
	"account-service/internal/models"
	
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JWT Secret Key - separate from PII encryption key
var jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))

type AccountRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	SIN      string `json:"sin"`
	Address  string `json:"address"`
	DOB      string `json:"dob"` // Date of birth
	Phone    string `json:"phone"`
}

type UpdatePhoneRequest struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// Simple rate limiter for login attempts
var (
	loginAttempts    = make(map[string]int)
	loginLockout     = make(map[string]time.Time)
	loginMu          sync.Mutex
	maxLoginAttempts = 5
	lockoutDuration  = 15 * time.Minute
)

func checkRateLimit(email string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	if lockoutTime, exists := loginLockout[email]; exists {
		if time.Now().Before(lockoutTime) {
			return false
		}
		delete(loginLockout, email)
		delete(loginAttempts, email)
	}
	return true
}

func recordFailedLogin(email string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	loginAttempts[email]++
	if loginAttempts[email] >= maxLoginAttempts {
		loginLockout[email] = time.Now().Add(lockoutDuration)
	}
}

func clearLoginAttempts(email string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginAttempts, email)
	delete(loginLockout, email)
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

	if os.Getenv("JWT_SECRET_KEY") == "" {
		log.Fatal("FATAL: JWT_SECRET_KEY is not set. Cannot start without JWT secret.")
	}
	if os.Getenv("PII_MASTER_KEY_B64") == "" {
		log.Fatal("FATAL: PII_MASTER_KEY_B64 is not set. Cannot start without encryption key.")
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

		if !checkRateLimit(req.Email) {
			http.Error(w, `{"message":"Too many login attempts. Please try again later."}`, http.StatusTooManyRequests)
			return
		}

		admin, err := models.GetAdminByEmail(context.Background(), pool, req.Email)
		if err != nil {
			log.Printf("AUDIT: Failed login attempt for %s", req.Email)
			recordFailedLogin(req.Email)
			http.Error(w, `{"message":"Invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		err = models.CompareHashAndPassword(admin.PasswordHash, req.Password)
		if err != nil {
			log.Printf("AUDIT: Failed login attempt for %s", req.Email)
			recordFailedLogin(req.Email)
			http.Error(w, `{"message":"Invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		clearLoginAttempts(req.Email)
		log.Printf("AUDIT: Admin login successful for %s (role: %s)", req.Email, admin.Role)

		expirationTime := time.Now().Add(30 * time.Minute)
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

		if req.Email == "" || req.Name == "" || req.Phone == "" {
			http.Error(w, `{"message":"Missing required fields (email, name, and phone are mandatory)"}`, http.StatusBadRequest)
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
		encPhone, _ := crypto.Encrypt(req.Phone, key)

		query := `
			INSERT INTO secure_accounts (email, encrypted_full_name, encrypted_sin, encrypted_address, encrypted_dob, encrypted_phone)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id;
		`
		var newID string
		err = pool.QueryRow(context.Background(), query, req.Email, encName, encSIN, encAddress, encDOB, encPhone).Scan(&newID)
		if err != nil {
			log.Printf("DB error: %v", err)
			http.Error(w, `{"message":"Failed to insert account"}`, http.StatusInternalServerError)
			return
		}

		log.Printf("AUDIT: Account created with ID %s by authenticated admin", newID)
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

		log.Printf("AUDIT: Account search performed for email %s", email)

		var acc models.Account
		query := `SELECT id, email, encrypted_full_name, encrypted_sin, encrypted_address, encrypted_dob, coalesce(encrypted_phone, '') FROM secure_accounts WHERE email = $1`
		err := pool.QueryRow(context.Background(), query, email).Scan(&acc.ID, &acc.Email, &acc.EncryptedFullName, &acc.EncryptedSIN, &acc.EncryptedAddress, &acc.EncryptedDOB, &acc.EncryptedPhone)
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
		fullSIN, _ := crypto.Decrypt(acc.EncryptedSIN, key)
		if len(fullSIN) >= 3 {
			acc.SIN = strings.Repeat("*", len(fullSIN)-3) + fullSIN[len(fullSIN)-3:]
		}
		acc.Address, _ = crypto.Decrypt(acc.EncryptedAddress, key)
		acc.DOB, _ = crypto.Decrypt(acc.EncryptedDOB, key)
		if acc.EncryptedPhone != "" {
			acc.Phone, _ = crypto.Decrypt(acc.EncryptedPhone, key)
		} else {
			acc.Phone = ""
		}

		// Don't send encrypted strings back to client
		acc.EncryptedFullName = ""
		acc.EncryptedSIN = ""
		acc.EncryptedAddress = ""
		acc.EncryptedDOB = ""
		acc.EncryptedPhone = ""

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acc)
	}))

	// Endpoint to update existing account phone number (MANAGER or SUPPORT)
	mux.HandleFunc("POST /admin/accounts/update-phone", rbacMiddleware([]string{"MANAGER", "SUPPORT"}, func(w http.ResponseWriter, r *http.Request) {
		var req UpdatePhoneRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Invalid JSON payload"}`, http.StatusBadRequest)
			return
		}

		if req.Email == "" || req.Phone == "" {
			http.Error(w, `{"message":"Missing required fields (email and phone are mandatory)"}`, http.StatusBadRequest)
			return
		}

		key, err := crypto.GetMasterKey()
		if err != nil {
			log.Printf("Crypto error: %v", err)
			http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
			return
		}

		encPhone, err := crypto.Encrypt(req.Phone, key)
		if err != nil {
			log.Printf("Crypto error: %v", err)
			http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
			return
		}

		query := `UPDATE secure_accounts SET encrypted_phone = $1, updated_at = NOW() WHERE email = $2`
		result, err := pool.Exec(context.Background(), query, encPhone, req.Email)
		if err != nil {
			log.Printf("DB error: %v", err)
			http.Error(w, `{"message":"Failed to update phone number"}`, http.StatusInternalServerError)
			return
		}

		rowsAffected := result.RowsAffected()
		if rowsAffected == 0 {
			http.Error(w, `{"message":"Account not found"}`, http.StatusNotFound)
			return
		}

		log.Printf("AUDIT: Phone number updated for account %s", req.Email)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"Phone number updated successfully"}`))
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
