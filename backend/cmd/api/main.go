package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"inglishorizon-backend/internal/crypto"
	"inglishorizon-backend/internal/db"
	"inglishorizon-backend/internal/ledger"
	"inglishorizon-backend/internal/models"
)

func main() {
	log.Println("Starting InglisHorizon Backend...")

	// Validate PII Master Key on startup
	if _, err := crypto.GetMasterKey(); err != nil {
		log.Fatalf("FATAL: Master encryption key validation failed: %v", err)
	}

	// Initialize Database connection
	database, err := db.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Initialize database tables
	if err := models.InitDB(context.Background(), database.Pool); err != nil {
		log.Fatalf("Failed to initialize merchant DB schema: %v", err)
	}

	// Initialize the Chi router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Base Routes
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to InglisHorizon Merchant API"))
	})

	// Merchant REST API
	r.Route("/merchants", func(r chi.Router) {
		// List all merchants
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			list, err := models.ListMerchants(r.Context(), database.Pool)
			if err != nil {
				log.Printf("Error listing merchants: %v", err)
				http.Error(w, `{"message":"Internal Server Error"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(list)
		})

		// Search merchant by email
		r.Get("/search", func(w http.ResponseWriter, r *http.Request) {
			queryStr := r.URL.Query().Get("q")
			if queryStr == "" {
				http.Error(w, `{"message":"Missing search query parameter 'q'"}`, http.StatusBadRequest)
				return
			}
			m, err := models.GetMerchantByEmail(r.Context(), database.Pool, queryStr)
			if err != nil {
				http.Error(w, `{"message":"Merchant not found"}`, http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(m)
		})

		// Create a new merchant
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var m models.Merchant
			if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
				http.Error(w, `{"message":"Invalid JSON payload"}`, http.StatusBadRequest)
				return
			}
			if m.ID == "" || m.Name == "" || m.Email == "" || m.Address == "" || m.NEQ == "" {
				http.Error(w, `{"message":"Missing required fields (id, name, email, address, neq)"}`, http.StatusBadRequest)
				return
			}
			err := models.CreateMerchant(r.Context(), database.Pool, &m)
			if err != nil {
				log.Printf("Error creating merchant: %v", err)
				http.Error(w, `{"message":"Failed to create merchant"}`, http.StatusInternalServerError)
				return
			}

			// Automatically create ledger accounts for the merchant (CAD, USD, EUR, JPY)
			if err := ledger.CreateMerchantAccounts(r.Context(), m.ID); err != nil {
				log.Printf("Warning: Failed to automatically create ledger accounts for merchant %s: %v", m.ID, err)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(m)
		})

		// Get, Update, Delete single merchant
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				id := chi.URLParam(r, "id")
				m, err := models.GetMerchant(r.Context(), database.Pool, id)
				if err != nil {
					http.Error(w, `{"message":"Merchant not found"}`, http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(m)
			})

			r.Put("/", func(w http.ResponseWriter, r *http.Request) {
				id := chi.URLParam(r, "id")
				var m models.Merchant
				if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
					http.Error(w, `{"message":"Invalid JSON payload"}`, http.StatusBadRequest)
					return
				}
				m.ID = id
				if m.Name == "" || m.Email == "" || m.Address == "" || m.NEQ == "" {
					http.Error(w, `{"message":"Missing required fields"}`, http.StatusBadRequest)
					return
				}
				err := models.UpdateMerchant(r.Context(), database.Pool, &m)
				if err != nil {
					log.Printf("Error updating merchant: %v", err)
					http.Error(w, `{"message":"Failed to update merchant"}`, http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(m)
			})

			r.Delete("/", func(w http.ResponseWriter, r *http.Request) {
				id := chi.URLParam(r, "id")
				err := models.DeleteMerchant(r.Context(), database.Pool, id)
				if err != nil {
					log.Printf("Error deleting merchant: %v", err)
					http.Error(w, `{"message":"Failed to delete merchant"}`, http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
		})
	})

	// Setup Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
	}

	log.Printf("Server listening on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
