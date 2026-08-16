package internal_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	gosrp "github.com/opencoff/go-srp"

	"github.com/masorange/maspassword/internal/handler"
	"github.com/masorange/maspassword/internal/oidc"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/internal/router"
	"github.com/masorange/maspassword/internal/service"
	"github.com/masorange/maspassword/internal/srp"
	"github.com/masorange/maspassword/pkg/dto"
)

func setupTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	db, err := sqlx.Connect("postgres", dbURL)
	if err != nil {
		t.Fatalf("connecting to db: %v", err)
	}

	// Clean tables for test isolation
	db.MustExec("DELETE FROM share_links")
	db.MustExec("DELETE FROM vault_teams")
	db.MustExec("DELETE FROM vault_keys")
	db.MustExec("DELETE FROM items")
	db.MustExec("DELETE FROM vaults")
	db.MustExec("DELETE FROM team_members")
	db.MustExec("DELETE FROM teams")
	db.MustExec("DELETE FROM users")

	jwtSecret := "test-secret-key-for-integration"

	srpEnv, err := srp.NewEnvironment(2048)
	if err != nil {
		t.Fatalf("creating SRP env: %v", err)
	}
	srpStore := srp.NewStore(5 * time.Minute)

	userRepo := repository.NewUserRepository(db)
	vaultRepo := repository.NewVaultRepository(db)
	itemRepo := repository.NewItemRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	vaultKeyRepo := repository.NewVaultKeyRepository(db)
	shareLinkRepo := repository.NewShareLinkRepository(db)

	authService := service.NewAuthService(userRepo, srpEnv, srpStore, jwtSecret)
	vaultService := service.NewVaultService(vaultRepo, vaultKeyRepo, teamRepo)
	itemService := service.NewItemService(itemRepo, vaultRepo, vaultKeyRepo)
	teamService := service.NewTeamService(teamRepo, userRepo, nil)
	shareLinkService := service.NewShareLinkService(shareLinkRepo, vaultRepo, itemRepo, teamRepo)

	authHandler := handler.NewAuthHandler(authService)
	vaultHandler := handler.NewVaultHandler(vaultService)
	itemHandler := handler.NewItemHandler(itemService)
	teamHandler := handler.NewTeamHandler(teamService)
	userHandler := handler.NewUserHandler(userRepo)
	shareLinkHandler := handler.NewShareLinkHandler(shareLinkService)
	settingsHandler := handler.NewSettingsHandler(repository.NewSettingsRepository(db))
	deviceRepo := repository.NewDeviceTokenRepository(db)
	deviceHandler := handler.NewDeviceHandler(deviceRepo)

	ssoHandler := handler.NewSSOHandler(oidc.NewRegistry(nil), jwtSecret, "", userRepo, nil)
	passkeyHandler := handler.NewPasskeyHandler(repository.NewPasskeyRepository(db), jwtSecret, "")
	r := router.Setup(authHandler, vaultHandler, itemHandler, teamHandler, userHandler, shareLinkHandler, settingsHandler, deviceHandler, ssoHandler, passkeyHandler, deviceRepo, jwtSecret, "*", false, nil, userRepo, nil, true, true, "test")
	ts := httptest.NewServer(r)

	cleanup := func() {
		ts.Close()
		db.MustExec("DELETE FROM share_links")
		db.MustExec("DELETE FROM vault_teams")
		db.MustExec("DELETE FROM vault_keys")
		db.MustExec("DELETE FROM items")
		db.MustExec("DELETE FROM vaults")
		db.MustExec("DELETE FROM team_members")
		db.MustExec("DELETE FROM teams")
		db.MustExec("DELETE FROM users")
		db.Close()
	}

	return ts, cleanup
}

func TestFullFlow(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	email := "integration@test.com"
	password := "super-secret-password"

	// === 1. Generate SRP verifier client-side ===
	srpInstance, err := gosrp.New(2048)
	if err != nil {
		t.Fatalf("creating SRP: %v", err)
	}

	verifier, err := srpInstance.Verifier([]byte(email), []byte(password))
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	_, encodedVerifier := verifier.Encode()

	// === 2. Signup ===
	signupBody, _ := json.Marshal(dto.SignupRequest{
		Email:       email,
		SRPSalt:     "client-generated-salt",
		SRPVerifier: encodedVerifier,
	})

	resp, err := http.Post(ts.URL+"/auth/signup", "application/json", bytes.NewReader(signupBody))
	if err != nil {
		t.Fatalf("signup request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("signup: expected 201, got %d: %v", resp.StatusCode, body)
	}
	t.Log("Signup: OK")

	// === 3. Login Step 1 ===
	// Create SRP client
	client, err := srpInstance.NewClient([]byte(email), []byte(password))
	if err != nil {
		t.Fatalf("creating SRP client: %v", err)
	}

	clientCreds := client.Credentials()

	step1Body, _ := json.Marshal(dto.LoginStep1Request{
		Email:        email,
		ClientPublic: clientCreds,
	})

	resp, err = http.Post(ts.URL+"/auth/login/step1", "application/json", bytes.NewReader(step1Body))
	if err != nil {
		t.Fatalf("login step1 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("login step1: expected 200, got %d: %v", resp.StatusCode, body)
	}

	var step1Resp dto.LoginStep1Response
	json.NewDecoder(resp.Body).Decode(&step1Resp)
	t.Logf("Login Step1: OK (session_id=%s)", step1Resp.SessionID)

	// === 4. Client generates proof ===
	clientProof, err := client.Generate(step1Resp.ServerPublic)
	if err != nil {
		t.Fatalf("generating client proof: %v", err)
	}

	// === 5. Login Step 2 ===
	step2Body, _ := json.Marshal(dto.LoginStep2Request{
		SessionID:   step1Resp.SessionID,
		ClientProof: clientProof,
	})

	resp, err = http.Post(ts.URL+"/auth/login/step2", "application/json", bytes.NewReader(step2Body))
	if err != nil {
		t.Fatalf("login step2 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("login step2: expected 200, got %d: %v", resp.StatusCode, body)
	}

	var step2Resp dto.LoginStep2Response
	json.NewDecoder(resp.Body).Decode(&step2Resp)

	if step2Resp.Token == "" {
		t.Fatal("login step2: no JWT token received")
	}

	// Verify server proof on client side
	if !client.ServerOk(step2Resp.ServerProof) {
		t.Fatal("server proof verification failed on client side")
	}
	t.Log("Login Step2: OK (JWT received, server proof verified)")

	token := step2Resp.Token

	// === 6. List vaults (empty) ===
	req, _ := http.NewRequest("GET", ts.URL+"/api/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list vaults: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list vaults: expected 200, got %d", resp.StatusCode)
	}

	var vaults []map[string]any
	json.NewDecoder(resp.Body).Decode(&vaults)
	if len(vaults) != 0 {
		t.Fatalf("expected 0 vaults, got %d", len(vaults))
	}
	t.Log("List Vaults (empty): OK")

	// === 7. Create vault ===
	createVaultBody, _ := json.Marshal(map[string]string{"name_encrypted": "encrypted-vault-name-base64"})
	req, _ = http.NewRequest("POST", ts.URL+"/api/vaults", bytes.NewReader(createVaultBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("create vault: expected 201, got %d: %v", resp.StatusCode, body)
	}

	var vault map[string]any
	json.NewDecoder(resp.Body).Decode(&vault)
	vaultID := vault["id"].(string)
	t.Logf("Create Vault: OK (id=%s)", vaultID)

	// === 8. Add item ===
	createItemBody, _ := json.Marshal(map[string]string{"data_encrypted": `"encrypted-item-data-base64"`})
	req, _ = http.NewRequest("POST", fmt.Sprintf("%s/api/vaults/%s/items", ts.URL, vaultID), bytes.NewReader(createItemBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create item: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("create item: expected 201, got %d: %v", resp.StatusCode, body)
	}

	var item map[string]any
	json.NewDecoder(resp.Body).Decode(&item)
	itemID := item["id"].(string)
	t.Logf("Create Item: OK (id=%s)", itemID)

	// === 9. List items ===
	req, _ = http.NewRequest("GET", fmt.Sprintf("%s/api/vaults/%s/items", ts.URL, vaultID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list items: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list items: expected 200, got %d", resp.StatusCode)
	}

	var items []map[string]any
	json.NewDecoder(resp.Body).Decode(&items)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	t.Log("List Items: OK (1 item)")

	// === 10. Update item with optimistic locking ===
	updateBody, _ := json.Marshal(map[string]any{
		"data_encrypted": `"updated-encrypted-data"`,
		"version":        1,
	})
	req, _ = http.NewRequest("PUT", fmt.Sprintf("%s/api/vaults/%s/items/%s", ts.URL, vaultID, itemID), bytes.NewReader(updateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update item: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("update item: expected 200, got %d: %v", resp.StatusCode, body)
	}
	t.Log("Update Item: OK (version bumped)")

	// === 11. Try stale update (should 409) ===
	staleBody, _ := json.Marshal(map[string]any{
		"data_encrypted": `"stale-data"`,
		"version":        1, // stale version
	})
	req, _ = http.NewRequest("PUT", fmt.Sprintf("%s/api/vaults/%s/items/%s", ts.URL, vaultID, itemID), bytes.NewReader(staleBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stale update: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale update: expected 409, got %d", resp.StatusCode)
	}
	t.Log("Optimistic Locking: OK (409 on stale version)")

	t.Log("=== Full integration test passed! ===")
}
