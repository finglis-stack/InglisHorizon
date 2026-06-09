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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
)

var (
	jwtToken string
	userRole string

	// URLs from environment variables with fallback
	accountAPIURL string
	bankingAPIURL string

	// Email validation regex
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

func init() {
	accountAPIURL = os.Getenv("ACCOUNT_SERVICE_URL")
	if accountAPIURL == "" {
		accountAPIURL = "https://account-service-production-24ae.up.railway.app"
	}
	bankingAPIURL = os.Getenv("LEDGER_SERVICE_URL")
	if bankingAPIURL == "" {
		bankingAPIURL = "https://ledger-service-production-7bdc.up.railway.app"
	}
}

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
	if err := survey.AskOne(promptEmail, &email); err != nil {
		fmt.Println("Erreur de saisie.")
		return
	}

	promptPassword := &survey.Password{
		Message: "Mot de passe:",
	}
	if err := survey.AskOne(promptPassword, &password); err != nil {
		fmt.Println("Erreur de saisie.")
		return
	}

	payload := map[string]interface{}{
		"email":    strings.TrimSpace(email),
		"password": strings.TrimSpace(password),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Erreur interne.")
		return
	}

	req, err := http.NewRequest("POST", accountAPIURL+"/admin/login", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Erreur de requête.")
		return
	}
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
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Println("ÉCHEC (Réponse invalide)")
			return
		}

		jwtToken = result["token"]
		userRole = result["role"]

		fmt.Printf("SUCCÈS ! (Rôle: %s)\n\n", userRole)
	} else {
		fmt.Println("ÉCHEC (Identifiants invalides)\n")
	}
}

func checkServerStatus() {
	client := &http.Client{Timeout: 5 * time.Second}
	fmt.Print("Pinging Server... ")

	var resp *http.Response
	var err error

	for i := 0; i < 3; i++ {
		resp, err = client.Get(accountAPIURL + "/health")
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
	if err := survey.AskOne(&survey.Input{Message: "Adresse courriel du client:"}, &email); err != nil {
		return
	}

	if !emailRegex.MatchString(email) {
		fmt.Println("Erreur: Adresse courriel invalide. Annulation.")
		return
	}

	var name string
	if err := survey.AskOne(&survey.Input{Message: "Nom complet du client:"}, &name); err != nil {
		return
	}

	// 2. Date de naissance & Calcul de l'âge
	var dob string
	for {
		if err := survey.AskOne(&survey.Input{Message: "Date de naissance (AAAA-MM-JJ):"}, &dob); err != nil {
			return
		}
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
	if err := survey.AskOne(&survey.Select{
		Message: "Région de résidence:",
		Options: []string{"Canada", "États-Unis"},
	}, &region); err != nil {
		return
	}

	var sin string
	sinLabel := "Numéro d'Assurance Sociale (NAS):"
	if region == "États-Unis" {
		sinLabel = "Social Security Number (SSN):"
	}

	for {
		if err := survey.AskOne(&survey.Input{Message: sinLabel}, &sin); err != nil {
			return
		}
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
	if err := survey.AskOne(&survey.Input{Message: "Recherche d'adresse (ex: 1000 de la gauchetiere, montreal):"}, &addressQuery); err != nil {
		return
	}

	addressOptions := searchOpenStreetMap(addressQuery)
	var finalAddress string

	if len(addressOptions) > 0 {
		if err := survey.AskOne(&survey.Select{
			Message: "Sélectionnez l'adresse validée :",
			Options: addressOptions,
		}, &finalAddress); err != nil {
			return
		}
	} else {
		fmt.Println(" Aucune recommandation trouvée. Saisie manuelle requise.")
		if err := survey.AskOne(&survey.Input{Message: "Adresse complète:"}, &finalAddress); err != nil {
			return
		}
	}

	// Confirmation finale
	var confirm bool
	if err := survey.AskOne(&survey.Confirm{
		Message: "Confirmez-vous la création de ce profil de haute sécurité ?",
		Default: true,
	}, &confirm); err != nil {
		return
	}

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
	if err := survey.AskOne(&survey.Input{Message: "Courriel du compte à rechercher :"}, &email); err != nil {
		return
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return
	}

	req, err := http.NewRequest("GET", accountAPIURL+"/admin/accounts/search?email="+url.QueryEscape(email), nil)
	if err != nil {
		fmt.Println("Erreur de requête.")
		return
	}
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

	// SIN is already masked by the server, display as-is
	sinDisplay, _ := acc["sin"].(string)

	fmt.Println("=========================================")
	fmt.Println("             DOSSIER CLIENT              ")
	fmt.Println("=========================================")
	fmt.Printf("Courriel     : %v\n", acc["email"])
	fmt.Printf("Nom Complet  : %v\n", acc["full_name"])
	fmt.Printf("Naiss. (Âge) : %v\n", ageStr)
	fmt.Printf("NAS          : %v\n", sinDisplay)
	fmt.Printf("Adresse      : %v\n", acc["address"])
	fmt.Println("=========================================")

	ownerID, ok := acc["id"].(string)
	if !ok {
		ownerID = ""
	}

	for {
		var action string
		if err := survey.AskOne(&survey.Select{
			Message: "Action sur ce dossier client :",
			Options: []string{
				"Consulter les comptes financiers",
				"Ouvrir un nouveau compte financier",
				"Fermer un compte financier",
				"Retour en arrière",
			},
		}, &action); err != nil {
			return
		}

		switch action {
		case "Consulter les comptes financiers":
			if ownerID == "" {
				if err := survey.AskOne(&survey.Input{Message: "Veuillez entrer l'ID du client (owner_id) :"}, &ownerID); err != nil {
					continue
				}
			}
			listFinancialAccounts(ownerID)
		case "Ouvrir un nouveau compte financier":
			if ownerID == "" {
				if err := survey.AskOne(&survey.Input{Message: "Veuillez entrer l'ID du client (owner_id) :"}, &ownerID); err != nil {
					continue
				}
			}
			createFinancialAccount(ownerID)
		case "Fermer un compte financier":
			var accountID string
			if err := survey.AskOne(&survey.Input{Message: "Veuillez entrer l'ID du compte financier à fermer :"}, &accountID); err != nil {
				continue
			}
			closeFinancialAccount(accountID)
		case "Retour en arrière":
			return
		}
	}
}

// authenticatedRequest creates an HTTP request with JWT auth header for ledger calls
func authenticatedRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if jwtToken != "" {
		req.Header.Set("Authorization", "Bearer "+jwtToken)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func listFinancialAccounts(ownerID string) {
	req, err := authenticatedRequest("GET", bankingAPIURL+"/ledger/owners/"+ownerID+"/accounts", nil)
	if err != nil {
		fmt.Println("Erreur de requête.")
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	fmt.Print("Récupération des comptes financiers... ")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ÉCHEC: Serveur bancaire injoignable.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("ÉCHEC (Code %d). Impossible de récupérer les comptes.\n", resp.StatusCode)
		return
	}

	var accounts []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&accounts); err != nil {
		fmt.Println("ÉCHEC: Données corrompues.")
		return
	}

	fmt.Println("SUCCÈS.\n")

	if len(accounts) == 0 {
		fmt.Println("Aucun compte financier trouvé pour ce client.")
		return
	}

	fmt.Println("=========================================")
	fmt.Println("           COMPTES FINANCIERS            ")
	fmt.Println("=========================================")
	for i, acc := range accounts {
		accID, ok := acc["id"].(string)
		if !ok {
			continue
		}

		// Fetch balance
		balReq, err := authenticatedRequest("GET", bankingAPIURL+"/ledger/accounts/"+accID, nil)
		var balanceStr string
		if err == nil {
			balResp, balErr := client.Do(balReq)
			if balErr == nil && balResp.StatusCode == http.StatusOK {
				var bData map[string]interface{}
				if json.NewDecoder(balResp.Body).Decode(&bData) == nil {
					if balFloat, ok := bData["balance"].(float64); ok {
						balanceStr = fmt.Sprintf("%.2f %s", balFloat/100.0, acc["currency"])
					} else {
						balanceStr = "N/A"
					}
				}
				balResp.Body.Close()
			} else {
				if balResp != nil {
					balResp.Body.Close()
				}
				balanceStr = "Erreur"
			}
		} else {
			balanceStr = "Erreur"
		}

		fmt.Printf("[%d] ID: %s | Type: %v | Devise: %v | Statut: %v\n", i+1, accID, acc["account_type"], acc["currency"], acc["status"])
		fmt.Printf("    Solde actuel: %s\n", balanceStr)
		if acc["account_type"] == "CREDIT" {
			fmt.Printf("    Taux d'intérêt: %v%%\n", acc["apr"])
		}
		fmt.Println("-----------------------------------------")
	}

	var accChoice string
	if err := survey.AskOne(&survey.Input{Message: "Entrez le numéro du compte pour voir les transactions (ou vide pour retourner) :"}, &accChoice); err != nil {
		return
	}
	if accChoice != "" {
		idx, err := strconv.Atoi(accChoice)
		if err == nil && idx >= 1 && idx <= len(accounts) {
			if id, ok := accounts[idx-1]["id"].(string); ok {
				viewAccountHistory(id)
			}
		}
	}
}

func viewAccountHistory(accountID string) {
	page := 1
	limit := 10
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		urlStr := fmt.Sprintf("%s/ledger/accounts/%s/transactions?page=%d&limit=%d", bankingAPIURL, accountID, page, limit)
		req, err := authenticatedRequest("GET", urlStr, nil)
		if err != nil {
			fmt.Println("Erreur de requête.")
			return
		}
		fmt.Printf("\n--- Chargement de la page %d ---\n", page)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("ÉCHEC: Serveur bancaire injoignable.")
			return
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("ÉCHEC (Code %d).\n", resp.StatusCode)
			resp.Body.Close()
			return
		}

		var data struct {
			Page         int `json:"page"`
			Limit        int `json:"limit"`
			Transactions []struct {
				ID        string `json:"id"`
				Type      string `json:"type"`
				Direction string `json:"direction"`
				Amount    int64  `json:"amount"`
				CreatedAt string `json:"created_at"`
			} `json:"transactions"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			fmt.Println("ÉCHEC: Données corrompues.")
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		fmt.Printf("=== HISTORIQUE DES TRANSACTIONS (Page %d) ===\n", page)
		if len(data.Transactions) == 0 {
			fmt.Println("  (Aucune transaction à afficher sur cette page)")
		} else {
			for _, tx := range data.Transactions {
				date, _ := time.Parse(time.RFC3339, tx.CreatedAt)
				amountFormatted := float64(tx.Amount) / 100.0
				sign := "+"
				if tx.Direction == "DEBIT" {
					sign = "-"
				}
				idShort := tx.ID
				if len(idShort) >= 8 {
					idShort = idShort[:8]
				}
				fmt.Printf("[%s] %s | %s | %s%.2f\n", date.Format("2006-01-02 15:04"), idShort, tx.Type, sign, amountFormatted)
			}
		}
		fmt.Println("============================================")

		var navChoice string
		options := []string{}
		if page > 1 {
			options = append(options, "Page Précédente")
		}
		if len(data.Transactions) == limit {
			options = append(options, "Page Suivante")
		}
		options = append(options, "Quitter l'historique")

		if err := survey.AskOne(&survey.Select{
			Message: "Navigation :",
			Options: options,
		}, &navChoice); err != nil {
			return
		}

		if navChoice == "Page Suivante" {
			page++
		} else if navChoice == "Page Précédente" {
			page--
		} else {
			break
		}
	}
}

func closeFinancialAccount(accountID string) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return
	}
	req, err := authenticatedRequest("POST", bankingAPIURL+"/ledger/accounts/"+accountID+"/close", nil)
	if err != nil {
		fmt.Println("Erreur de requête.")
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	fmt.Print("Fermeture du compte financier... ")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ÉCHEC: Serveur bancaire injoignable.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("SUCCÈS. Le compte a été fermé avec succès.")
	} else {
		fmt.Printf("ÉCHEC (Code %d). Le compte n'a pas pu être fermé ou est déjà fermé.\n", resp.StatusCode)
	}
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

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		fmt.Println("ÉCHEC")
		return nil
	}
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
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Erreur: Impossible de préparer les données.")
		return
	}

	req, err := http.NewRequest("POST", accountAPIURL+"/admin/accounts", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Erreur: Impossible de créer la requête.")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	client := &http.Client{Timeout: 15 * time.Second}
	fmt.Print("\nConnexion au serveur sécurisé... ")

	var resp *http.Response
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("\nÉCHEC: Impossible de lire la réponse.")
		return
	}

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		fmt.Println("SUCCÈS !")
		newID := string(bodyBytes)
		fmt.Printf("UUID Sécurisé: %s\n\n", newID)
	} else {
		fmt.Println("ÉCHEC.")
		var errData map[string]interface{}
		if json.Unmarshal(bodyBytes, &errData) == nil && errData["message"] != nil {
			fmt.Printf("Raison: %v\n\n", errData["message"])
		} else {
			fmt.Printf("Code HTTP: %d\n\n", resp.StatusCode)
		}
	}
}

func createFinancialAccount(ownerID string) {
	var createFinancial bool
	if err := survey.AskOne(&survey.Confirm{
		Message: "Voulez-vous ouvrir un compte financier pour cet utilisateur ?",
		Default: true,
	}, &createFinancial); err != nil {
		return
	}

	if !createFinancial {
		return
	}

	var currency, accType string
	var apr float64

	if err := survey.AskOne(&survey.Select{
		Message: "Devise du compte (ISO 4217) :",
		Options: []string{"CAD", "USD", "EUR", "JPY"},
		Default: "CAD",
	}, &currency); err != nil {
		return
	}

	if err := survey.AskOne(&survey.Select{
		Message: "Type de compte :",
		Options: []string{"DEPOSIT (Débit/Dépôt)", "CREDIT (Marge/Carte)"},
	}, &accType); err != nil {
		return
	}

	if strings.HasPrefix(accType, "CREDIT") {
		accType = "CREDIT"
		var aprStr string
		if err := survey.AskOne(&survey.Input{Message: "Taux d'intérêt annuel (APR) % (ex: 19.99) :"}, &aprStr); err != nil {
			return
		}
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

	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Erreur interne.")
		return
	}

	req, err := authenticatedRequest("POST", bankingAPIURL+"/ledger/accounts", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Erreur de requête.")
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	fmt.Print("\nCréation du compte au système bancaire central... ")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ÉCHEC: Serveur bancaire injoignable.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		fmt.Println("ÉCHEC de la création du compte financier.")
		return
	}

	fmt.Println("SUCCÈS. Le compte a été activé sur le système bancaire.")
}
