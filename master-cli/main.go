package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
)

const (
	defaultAccountAPIURL = "https://account-service-production-8482.up.railway.app"
	defaultLedgerAPIURL  = "http://localhost:8483" // To be updated when deployed to Railway
)

var (
	jwtToken string
	userRole string
)

func main() {
	fmt.Println("========================================")
	fmt.Println("       INGLIS HORIZON MASTER CLI        ")
	fmt.Println("========================================")
	fmt.Println("Tapez 'help' pour la liste des commandes.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		if jwtToken == "" {
			fmt.Print("Inglis (Non connecté)> ")
		} else {
			fmt.Printf("Inglis (%s)> ", userRole)
		}

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		args := strings.Fields(input)
		cmd := strings.ToLower(args[0])

		switch cmd {
		case "help":
			fmt.Println("\nCommandes disponibles :")
			fmt.Println("  login                           - S'authentifier au réseau sécurisé")
			fmt.Println("  create-account                  - Démarrer l'assistant de création (Requis: MANAGER)")
			fmt.Println("  search                          - Rechercher un dossier client par courriel")
			fmt.Println("  status                          - Vérifier la connexion serveur")
			fmt.Println("  clear                           - Nettoyer l'écran")
			fmt.Println("  logout                          - Se déconnecter")
			fmt.Println("  exit                            - Quitter\n")

		case "login":
			performInteractiveLogin()

		case "logout":
			jwtToken = ""
			userRole = ""
			fmt.Println("Déconnexion réussie.")

		case "status":
			checkServerStatus()

		case "create-account":
			if jwtToken == "" {
				fmt.Println("Erreur: Vous devez être connecté (utilisez la commande 'login').")
				continue
			}
			interactiveCreateAccount()

		case "search":
			if jwtToken == "" {
				fmt.Println("Erreur: Vous devez être connecté.")
				continue
			}
			searchAccount()

		case "clear":
			fmt.Print("\033[H\033[2J")

		case "exit", "quit":
			return

		default:
			fmt.Printf("Commande inconnue: '%s'. Tapez 'help'.\n", cmd)
		}
	}
}

func performInteractiveLogin() {
	var email string
	var password string

	promptEmail := &survey.Input{
		Message: "Courriel administrateur:",
	}
	survey.AskOne(promptEmail, &email)

	promptPassword := &survey.Password{
		Message: "Mot de passe:",
	}
	survey.AskOne(promptPassword, &password)

	payload := map[string]interface{}{
		"email":    strings.TrimSpace(email),
		"password": strings.TrimSpace(password),
	}

	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", defaultAccountAPIURL+"/admin/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}

	fmt.Print("Authentification en cours... ")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ÉCHEC (Serveur injoignable)")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)

		jwtToken = result["token"]
		userRole = result["role"]

		fmt.Printf("SUCCÈS ! (Rôle: %s)\n\n", userRole)
	} else {
		fmt.Println("ÉCHEC (Identifiants invalides)\n")
	}
}

func checkServerStatus() {
	client := &http.Client{Timeout: 5 * time.Second}
	fmt.Print("Pinging Railway Server... ")

	var resp *http.Response
	var err error

	for i := 0; i < 3; i++ {
		resp, err = client.Get(defaultAccountAPIURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		fmt.Println("ÉCHEC (Serveur injoignable ou hors ligne)")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("EN LIGNE")
	} else if resp.StatusCode == 502 || resp.StatusCode == 503 {
		fmt.Printf("EN DÉMARRAGE (Status: %d)\n", resp.StatusCode)
	} else {
		fmt.Printf("ERREUR (Status: %d)\n", resp.StatusCode)
	}
}

// ---------------------------------------------------------
// WIZARD CREATION DE COMPTE INTERACTIF
// ---------------------------------------------------------

func interactiveCreateAccount() {
	fmt.Println("\n--- Assistant de Provisionnement de Compte ---")
	
	// 1. Email et Nom
	var email string
	survey.AskOne(&survey.Input{Message: "Adresse courriel du client:"}, &email)
	
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		fmt.Println("Erreur: Adresse courriel invalide. Annulation.")
		return
	}

	var name string
	survey.AskOne(&survey.Input{Message: "Nom complet du client:"}, &name)

	// 2. Date de naissance & Calcul de l'âge
	var dob string
	for {
		survey.AskOne(&survey.Input{Message: "Date de naissance (AAAA-MM-JJ):"}, &dob)
		age, err := calculateAge(dob)
		if err != nil {
			fmt.Println(" Format invalide. Veuillez utiliser AAAA-MM-JJ.")
			continue
		}
		fmt.Printf(" => [Âge calculé : %d ans]\n", age)
		break
	}

	// 3. Région & NAS / SSN
	var region string
	survey.AskOne(&survey.Select{
		Message: "Région de résidence:",
		Options: []string{"Canada", "États-Unis"},
	}, &region)

	var sin string
	sinLabel := "Numéro d'Assurance Sociale (NAS):"
	if region == "États-Unis" {
		sinLabel = "Social Security Number (SSN):"
	}

	for {
		survey.AskOne(&survey.Input{Message: sinLabel}, &sin)
		// Nettoyage des tirets et espaces
		cleanSIN := strings.ReplaceAll(sin, "-", "")
		cleanSIN = strings.ReplaceAll(cleanSIN, " ", "")
		
		if !isValidLuhn(cleanSIN) {
			fmt.Println(" Numéro invalide (Échec de la validation Luhn). Veuillez réessayer.")
			continue
		}
		fmt.Println(" Numéro mathématiquement valide.")
		sin = cleanSIN // On garde la version propre
		break
	}

	// 4. Adresse
	var addressQuery string
	survey.AskOne(&survey.Input{Message: "Recherche d'adresse (ex: 1000 de la gauchetiere, montreal):"}, &addressQuery)
	
	addressOptions := searchOpenStreetMap(addressQuery)
	var finalAddress string
	
	if len(addressOptions) > 0 {
		survey.AskOne(&survey.Select{
			Message: "Sélectionnez l'adresse validée :",
			Options: addressOptions,
		}, &finalAddress)
	} else {
		fmt.Println(" Aucune recommandation trouvée. Saisie manuelle requise.")
		survey.AskOne(&survey.Input{Message: "Adresse complète:"}, &finalAddress)
	}

	// Confirmation finale
	var confirm bool
	survey.AskOne(&survey.Confirm{
		Message: "Confirmez-vous la création de ce profil de haute sécurité ?",
		Default: true,
	}, &confirm)

	if !confirm {
		fmt.Println("Annulation de l'opération.")
		return
	}

	// Envoi du payload
	payload := map[string]interface{}{
		"email":   email,
		"name":    name,
		"sin":     sin,
		"address": finalAddress,
		"dob":     dob,
	}

	sendAccountPayload(payload)
}

func searchAccount() {
	var email string
	survey.AskOne(&survey.Input{Message: "Courriel du compte à rechercher :"}, &email)
	email = strings.TrimSpace(email)
	if email == "" {
		return
	}

	req, _ := http.NewRequest("GET", defaultAccountAPIURL+"/admin/accounts/search?email="+url.QueryEscape(email), nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	client := &http.Client{Timeout: 10 * time.Second}
	fmt.Print("Recherche sécurisée en cours... ")
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ÉCHEC: Serveur injoignable.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Println("AUCUN RÉSULTAT. Ce courriel n'existe pas dans la base de données.")
		return
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Println("ÉCHEC. Erreur du serveur ou accès refusé.")
		return
	}

	var acc map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&acc); err != nil {
		fmt.Println("ÉCHEC: Données corrompues.")
		return
	}

	fmt.Println("SUCCÈS.\n")
	
	dobStr, _ := acc["dob"].(string)
	ageStr := dobStr
	if dobStr != "" {
		age, err := calculateAge(dobStr)
		if err == nil {
			ageStr = fmt.Sprintf("%s (%d ans)", dobStr, age)
		}
	}

	fmt.Println("=========================================")
	fmt.Println("             DOSSIER CLIENT              ")
	fmt.Println("=========================================")
	fmt.Printf("Courriel     : %v\n", acc["email"])
	fmt.Printf("Nom Complet  : %v\n", acc["full_name"])
	fmt.Printf("Naiss. (Âge) : %v\n", ageStr)
	fmt.Printf("NAS          : %v\n", acc["sin"])
	fmt.Printf("Adresse      : %v\n", acc["address"])
	fmt.Println("=========================================")
}

func calculateAge(dobStr string) (int, error) {
	dob, err := time.Parse("2006-01-02", dobStr)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	age := now.Year() - dob.Year()
	if now.YearDay() < dob.YearDay() {
		age--
	}
	return age, nil
}

func isValidLuhn(number string) bool {
	if number == "" {
		return false
	}
	sum := 0
	alternate := false
	for i := len(number) - 1; i >= 0; i-- {
		n, err := strconv.Atoi(string(number[i]))
		if err != nil {
			return false
		}
		if alternate {
			n *= 2
			if n > 9 {
				n = (n % 10) + 1
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

func searchOpenStreetMap(query string) []string {
	fmt.Print(" Recherche en cours... ")
	
	client := &http.Client{Timeout: 5 * time.Second}
	reqURL := fmt.Sprintf("https://nominatim.openstreetmap.org/search?q=%s&format=json&limit=5", url.QueryEscape(query))
	
	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("User-Agent", "InglisHorizon-MasterCLI/1.0")
	
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("ÉCHEC")
		return nil
	}
	defer resp.Body.Close()

	var results []struct {
		DisplayName string `json:"display_name"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		fmt.Println("ÉCHEC")
		return nil
	}
	
	fmt.Println("Trouvé !")
	var options []string
	for _, r := range results {
		options = append(options, r.DisplayName)
	}
	
	// Option fallback
	options = append(options, "[Saisie Manuelle]")
	return options
}

func sendAccountPayload(payload map[string]interface{}) {
	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", defaultAccountAPIURL+"/admin/accounts", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	client := &http.Client{Timeout: 15 * time.Second}
	fmt.Print("\nConnexion au serveur sécurisé... ")

	var resp *http.Response
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			break
		}
		if attempt < 3 {
			fmt.Printf("\n[Serveur occupé, tentative %d/3 dans 2 secondes...] ", attempt+1)
			time.Sleep(2 * time.Second)
			req.Body = io.NopCloser(bytes.NewBuffer(jsonData))
		}
	}

	if err != nil {
		fmt.Println("\nÉCHEC: Impossible de joindre le serveur.")
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		fmt.Println("SUCCÈS !")
		newID := string(bodyBytes)
		fmt.Printf("UUID Sécurisé: %s\n\n", newID)
		createLedgerAccount(newID)
	} else {
		fmt.Println("ÉCHEC.")
		var errData map[string]interface{}
		if json.Unmarshal(bodyBytes, &errData) == nil && errData["message"] != nil {
			fmt.Printf("Raison: %v\n\n", errData["message"])
		} else {
			fmt.Printf("Code HTTP: %d\nDétails bruts: %s\n\n", resp.StatusCode, string(bodyBytes))
		}
	}
}

func createLedgerAccount(ownerID string) {
	var createLedger bool
	survey.AskOne(&survey.Confirm{
		Message: "Voulez-vous ouvrir un compte financier (Ledger) pour cet utilisateur ?",
		Default: true,
	}, &createLedger)

	if !createLedger {
		return
	}

	var currency, accType string
	var apr float64

	survey.AskOne(&survey.Select{
		Message: "Devise du compte (ISO 4217) :",
		Options: []string{"CAD", "USD", "EUR", "JPY"},
		Default: "CAD",
	}, &currency)

	survey.AskOne(&survey.Select{
		Message: "Type de compte :",
		Options: []string{"DEPOSIT (Débit/Dépôt)", "CREDIT (Marge/Carte)"},
	}, &accType)

	if strings.HasPrefix(accType, "CREDIT") {
		accType = "CREDIT"
		var aprStr string
		survey.AskOne(&survey.Input{Message: "Taux d'intérêt annuel (APR) % (ex: 19.99) :"}, &aprStr)
		fmt.Sscanf(aprStr, "%f", &apr)
	} else {
		accType = "DEPOSIT"
	}

	payload := map[string]interface{}{
		"owner_id":     ownerID,
		"currency":     currency,
		"account_type": accType,
		"apr":          apr,
	}

	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", defaultLedgerAPIURL+"/ledger/accounts", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	fmt.Print("\nCréation du coffre financier... ")
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ÉCHEC: Serveur Ledger injoignable.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		fmt.Println("ÉCHEC de la création du compte financier.")
		return
	}

	fmt.Println("SUCCÈS. Le compte a été activé sur le grand livre.")
}
