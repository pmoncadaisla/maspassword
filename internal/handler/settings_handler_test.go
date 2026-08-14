package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/repository"
)

// fakeSettingsRepo is an in-memory repository.SettingsRepository.
type fakeSettingsRepo struct {
	values map[string]string
	getErr error
	putErr error
}

func newFakeSettingsRepo() *fakeSettingsRepo {
	return &fakeSettingsRepo{values: map[string]string{}}
}

func (f *fakeSettingsRepo) Get(_ context.Context, key string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.values[key], nil
}

func (f *fakeSettingsRepo) Upsert(_ context.Context, key, value string) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.values[key] = value
	return nil
}

func TestThemeValidation(t *testing.T) {
	valid := []string{"light", "orange"}
	invalid := []string{"", "dark", "LIGHT", "Orange", "blue", " light"}

	for _, v := range valid {
		if !IsValidTheme(v) {
			t.Errorf("IsValidTheme(%q) = false, want true", v)
		}
		if got := NormalizeTheme(v); got != v {
			t.Errorf("NormalizeTheme(%q) = %q, want %q", v, got, v)
		}
	}
	for _, v := range invalid {
		if IsValidTheme(v) {
			t.Errorf("IsValidTheme(%q) = true, want false", v)
		}
		if got := NormalizeTheme(v); got != ThemeLight {
			t.Errorf("NormalizeTheme(%q) = %q, want %q", v, got, ThemeLight)
		}
	}
}

func TestDefaultTheme(t *testing.T) {
	repo := newFakeSettingsRepo()
	h := NewSettingsHandler(repo)

	if got := h.DefaultTheme(context.Background()); got != "light" {
		t.Errorf("unset default theme = %q, want light", got)
	}

	repo.values[repository.SettingKeyDefaultTheme] = "orange"
	if got := h.DefaultTheme(context.Background()); got != "orange" {
		t.Errorf("default theme = %q, want orange", got)
	}

	repo.values[repository.SettingKeyDefaultTheme] = "bogus"
	if got := h.DefaultTheme(context.Background()); got != "light" {
		t.Errorf("bogus stored theme = %q, want light", got)
	}

	repo.getErr = errors.New("db down")
	if got := h.DefaultTheme(context.Background()); got != "light" {
		t.Errorf("errored read = %q, want light (degrade gracefully)", got)
	}
}

func settingsTestRouter(repo repository.SettingsRepository) *gin.Engine {
	h := NewSettingsHandler(repo)
	r := gin.New()
	r.GET("/api/admin/settings", h.GetSettings)
	r.PUT("/api/admin/settings", h.UpdateSettings)
	return r
}

func TestGetSettings_DefaultsToLight(t *testing.T) {
	r := settingsTestRouter(newFakeSettingsRepo())

	req := httptest.NewRequest(http.MethodGet, "/api/admin/settings", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["default_theme"] != "light" {
		t.Errorf("default_theme = %q, want light", body["default_theme"])
	}
}

func TestUpdateSettings_UpsertsAndEchoes(t *testing.T) {
	repo := newFakeSettingsRepo()
	r := settingsTestRouter(repo)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/settings",
		bytes.NewReader([]byte(`{"default_theme":"orange"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["default_theme"] != "orange" {
		t.Errorf("echoed default_theme = %q, want orange", body["default_theme"])
	}
	if repo.values[repository.SettingKeyDefaultTheme] != "orange" {
		t.Errorf("stored value = %q, want orange", repo.values[repository.SettingKeyDefaultTheme])
	}
}

func TestUpdateSettings_RejectsInvalidTheme(t *testing.T) {
	repo := newFakeSettingsRepo()
	r := settingsTestRouter(repo)

	for _, payload := range []string{
		`{"default_theme":"dark"}`,
		`{"default_theme":""}`,
		`{}`,
		`not json`,
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/admin/settings",
			bytes.NewReader([]byte(payload)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("payload %s: expected 400, got %d", payload, w.Code)
		}
	}
	if len(repo.values) != 0 {
		t.Errorf("invalid payloads must not write settings, got %v", repo.values)
	}
}

func TestUpdateSettings_RepoErrorIs500(t *testing.T) {
	repo := newFakeSettingsRepo()
	repo.putErr = errors.New("db down")
	r := settingsTestRouter(repo)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/settings",
		bytes.NewReader([]byte(`{"default_theme":"light"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}
