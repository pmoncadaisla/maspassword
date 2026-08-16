package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectAll(t *testing.T) {
	// Trailing slash on the target must not produce double slashes.
	h := RedirectAll("https://opensesamo.com/")

	for _, tc := range []struct{ path, want string }{
		{"/", "https://opensesamo.com/"},
		{"/app", "https://opensesamo.com/app"},
		{"/auth/mode", "https://opensesamo.com/auth/mode"},
		{"/app?next=%2Fvault%2F1&x=2", "https://opensesamo.com/app?next=%2Fvault%2F1&x=2"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != tc.want {
			t.Errorf("GET %s = %d %q, want 301 %q", tc.path, w.Code, w.Header().Get("Location"), tc.want)
		}
	}

	// Non-GET requests (API clients) get the same permanent signal.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/vaults", nil))
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "https://opensesamo.com/api/vaults" {
		t.Errorf("POST /api/vaults = %d %q, want 301 to the new origin", w.Code, w.Header().Get("Location"))
	}
}
