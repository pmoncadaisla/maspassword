package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	gosrp "github.com/opencoff/go-srp"
)

const baseURL = "http://localhost:8080"

var token string

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "signup":
		if len(os.Args) != 4 {
			fmt.Println("Usage: client signup <email> <password>")
			os.Exit(1)
		}
		signup(os.Args[2], os.Args[3])

	case "login":
		if len(os.Args) != 4 {
			fmt.Println("Usage: client login <email> <password>")
			os.Exit(1)
		}
		login(os.Args[2], os.Args[3])

	case "vaults":
		if len(os.Args) < 3 {
			fmt.Println("Usage: client vaults <token> [list|create <name_encrypted>]")
			os.Exit(1)
		}
		token = os.Args[2]
		if len(os.Args) == 3 || os.Args[3] == "list" {
			listVaults()
		} else if os.Args[3] == "create" && len(os.Args) == 5 {
			createVault(os.Args[4])
		} else {
			fmt.Println("Usage: client vaults <token> [list|create <name_encrypted>]")
		}

	case "items":
		if len(os.Args) < 4 {
			fmt.Println("Usage: client items <token> <vault_id> [list|create <data>|update <item_id> <data> <version>]")
			os.Exit(1)
		}
		token = os.Args[2]
		vaultID := os.Args[3]
		if len(os.Args) == 4 || os.Args[4] == "list" {
			listItems(vaultID)
		} else if os.Args[4] == "create" && len(os.Args) == 6 {
			createItem(vaultID, os.Args[5])
		} else if os.Args[4] == "update" && len(os.Args) == 8 {
			updateItem(vaultID, os.Args[5], os.Args[6], os.Args[7])
		} else {
			fmt.Println("Usage: client items <token> <vault_id> [list|create <data>|update <item_id> <data> <version>]")
		}

	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`Vault-Internal CLI Client

Usage:
  client signup <email> <password>
  client login  <email> <password>
  client vaults <token> list
  client vaults <token> create <name_encrypted>
  client items  <token> <vault_id> list
  client items  <token> <vault_id> create <data_encrypted>
  client items  <token> <vault_id> update <item_id> <data_encrypted> <version>

Flow:
  1. signup  → creates account (stores SRP verifier, server never sees password)
  2. login   → SRP-6a handshake → returns JWT token
  3. vaults  → create/list encrypted vaults (use token from login)
  4. items   → create/list/update encrypted items inside a vault`)
}

func signup(email, password string) {
	srp, err := gosrp.New(2048)
	if err != nil {
		fatal("SRP init: %v", err)
	}

	verifier, err := srp.Verifier([]byte(email), []byte(password))
	if err != nil {
		fatal("Creating verifier: %v", err)
	}

	_, encodedVerifier := verifier.Encode()

	body := map[string]string{
		"email":        email,
		"srp_salt":     "client-salt",
		"srp_verifier": encodedVerifier,
	}

	resp := post("/auth/signup", body)
	fmt.Println("Signup OK:")
	prettyPrint(resp)
}

func login(email, password string) {
	srpInstance, err := gosrp.New(2048)
	if err != nil {
		fatal("SRP init: %v", err)
	}

	// Create SRP client
	client, err := srpInstance.NewClient([]byte(email), []byte(password))
	if err != nil {
		fatal("Creating SRP client: %v", err)
	}

	clientCreds := client.Credentials()

	// Step 1: Send client credentials
	step1Body := map[string]string{
		"email":         email,
		"client_public": clientCreds,
	}
	step1Resp := post("/auth/login/step1", step1Body)

	var step1 struct {
		SessionID    string `json:"session_id"`
		Salt         string `json:"salt"`
		ServerPublic string `json:"server_public"`
	}
	json.Unmarshal(step1Resp, &step1)

	fmt.Printf("Step 1 OK (session: %s)\n", step1.SessionID)

	// Generate client proof
	clientProof, err := client.Generate(step1.ServerPublic)
	if err != nil {
		fatal("Generating proof: %v", err)
	}

	// Step 2: Send proof
	step2Body := map[string]string{
		"session_id":   step1.SessionID,
		"client_proof": clientProof,
	}
	step2Resp := post("/auth/login/step2", step2Body)

	var step2 struct {
		Token       string `json:"token"`
		ServerProof string `json:"server_proof"`
	}
	json.Unmarshal(step2Resp, &step2)

	// Verify server
	if !client.ServerOk(step2.ServerProof) {
		fatal("Server proof verification FAILED — possible MITM!")
	}

	fmt.Println("Login OK — server identity verified")
	fmt.Printf("\nToken (use this for subsequent requests):\n%s\n", step2.Token)
}

func listVaults() {
	resp := get("/api/vaults")
	fmt.Println("Vaults:")
	prettyPrint(resp)
}

func createVault(nameEncrypted string) {
	body := map[string]string{"name_encrypted": nameEncrypted}
	resp := post("/api/vaults", body)
	fmt.Println("Vault created:")
	prettyPrint(resp)
}

func listItems(vaultID string) {
	resp := get(fmt.Sprintf("/api/vaults/%s/items", vaultID))
	fmt.Println("Items:")
	prettyPrint(resp)
}

func createItem(vaultID, dataEncrypted string) {
	body := map[string]string{"data_encrypted": dataEncrypted}
	resp := post(fmt.Sprintf("/api/vaults/%s/items", vaultID), body)
	fmt.Println("Item created:")
	prettyPrint(resp)
}

func updateItem(vaultID, itemID, dataEncrypted, version string) {
	var v int
	fmt.Sscanf(version, "%d", &v)
	body := map[string]any{"data_encrypted": dataEncrypted, "version": v}
	resp := put(fmt.Sprintf("/api/vaults/%s/items/%s", vaultID, itemID), body)
	fmt.Println("Item updated:")
	prettyPrint(resp)
}

// --- HTTP helpers ---

func post(path string, body any) []byte {
	return doRequest("POST", path, body)
}

func put(path string, body any) []byte {
	return doRequest("PUT", path, body)
}

func get(path string) []byte {
	return doRequest("GET", path, nil)
}

func doRequest(method, path string, body any) []byte {
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, baseURL+path, reqBody)
	if err != nil {
		fatal("Creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal("Request failed: %v", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		fmt.Printf("Error %d:\n", resp.StatusCode)
		prettyPrint(data)
		os.Exit(1)
	}

	return data
}

func prettyPrint(data []byte) {
	var out bytes.Buffer
	if err := json.Indent(&out, data, "", "  "); err != nil {
		fmt.Println(string(data))
		return
	}
	fmt.Println(out.String())
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
