package mailer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDisabledMailerIsNoOp(t *testing.T) {
	m := New(Config{}) // no key, no domain
	if m.Enabled() {
		t.Fatal("mailer without credentials must be disabled")
	}
	if err := m.Send(context.Background(), "a@b.c", "subject", "<p>hi</p>", "hi"); err != nil {
		t.Fatalf("disabled Send must be a no-op, got %v", err)
	}

	// Only key, no domain → still disabled.
	m = New(Config{APIKey: "key"})
	if m.Enabled() {
		t.Fatal("mailer without domain must be disabled")
	}

	// Nil mailer is safe too.
	var nilMailer *Mailer
	if nilMailer.Enabled() {
		t.Fatal("nil mailer must report disabled")
	}
	if err := nilMailer.Send(context.Background(), "a@b.c", "s", "h", "t"); err != nil {
		t.Fatalf("nil mailer Send must be a no-op, got %v", err)
	}
	if err := nilMailer.SendMemberInvited(context.Background(), "a@b.c", "Equipo", "Ana", "member"); err != nil {
		t.Fatalf("nil mailer SendMemberInvited must be a no-op, got %v", err)
	}
}

func TestRenderInviteMember(t *testing.T) {
	subject, html, text, err := RenderInviteMember("Equipo Seguridad", "Ana García", "member", "https://mp.example.com")
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if !strings.Contains(subject, "Equipo Seguridad") {
		t.Errorf("subject missing team name: %q", subject)
	}
	for _, want := range []string{"Ana García", "Equipo Seguridad", "member", "https://mp.example.com", "MasPassword", "mensaje autom"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	for _, want := range []string{"Ana García", "Equipo Seguridad", "member", "https://mp.example.com", "mensaje autom"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q", want)
		}
	}
	if strings.Contains(text, "<") {
		t.Errorf("text part must not contain markup: %q", text)
	}
}

func TestRenderInviteMemberWithoutBaseURLHasNoButton(t *testing.T) {
	_, html, text, err := RenderInviteMember("Equipo", "Ana", "member", "")
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if strings.Contains(html, "Abrir MasPassword") {
		t.Error("button must be omitted when base URL is empty")
	}
	if strings.Contains(text, "Abrir MasPassword") {
		t.Error("text link must be omitted when base URL is empty")
	}
}

func TestRenderInviteAdmins(t *testing.T) {
	subject, html, text, err := RenderInviteAdmins("Equipo X", "Ana", "Pablo Moncada", "member")
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if !strings.Contains(subject, "Equipo X") {
		t.Errorf("subject missing team name: %q", subject)
	}
	for _, want := range []string{"Ana", "Pablo Moncada", "Equipo X", "member"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q", want)
		}
	}
}

func TestRenderPromoteAdmins(t *testing.T) {
	subject, html, text, err := RenderPromoteAdmins("Equipo X", "Ana", "Pablo")
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if !strings.Contains(subject, "Pablo") || !strings.Contains(subject, "Equipo X") {
		t.Errorf("subject missing member/team: %q", subject)
	}
	for _, want := range []string{"Pablo", "Equipo X", "Ana", "administrador"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q", want)
		}
	}
}

func TestTemplatesEscapeHTML(t *testing.T) {
	_, html, _, err := RenderInviteMember(`<script>alert(1)</script>`, "Ana", "member", "")
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if strings.Contains(html, "<script>") {
		t.Error("team name must be HTML-escaped")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected escaped team name in html")
	}
}

func TestSendPostsMailgunForm(t *testing.T) {
	var gotPath, gotUser, gotPass string
	var gotForm map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUser, gotPass, _ = r.BasicAuth()
		if err := r.ParseForm(); err != nil {
			t.Errorf("parsing form: %v", err)
		}
		gotForm = map[string]string{
			"from":    r.PostFormValue("from"),
			"to":      r.PostFormValue("to"),
			"subject": r.PostFormValue("subject"),
			"html":    r.PostFormValue("html"),
			"text":    r.PostFormValue("text"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := New(Config{APIKey: "key-123", Domain: "mg.example.com"})
	m.apiBase = srv.URL // point at the test server

	if !m.Enabled() {
		t.Fatal("mailer with key+domain must be enabled")
	}
	if err := m.Send(context.Background(), "dest@example.com", "Hola", "<p>Hola</p>", "Hola"); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	if gotPath != "/v3/mg.example.com/messages" {
		t.Errorf("unexpected path %q", gotPath)
	}
	if gotUser != "api" || gotPass != "key-123" {
		t.Errorf("unexpected basic auth %q:%q", gotUser, gotPass)
	}
	want := map[string]string{
		"from":    "MasPassword <noreply@mg.example.com>",
		"to":      "dest@example.com",
		"subject": "Hola",
		"html":    "<p>Hola</p>",
		"text":    "Hola",
	}
	for k, v := range want {
		if gotForm[k] != v {
			t.Errorf("form field %s = %q, want %q", k, gotForm[k], v)
		}
	}
}

func TestSendReturnsErrorOnAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := New(Config{APIKey: "bad", Domain: "mg.example.com"})
	m.apiBase = srv.URL

	if err := m.Send(context.Background(), "dest@example.com", "Hola", "<p>Hola</p>", "Hola"); err == nil {
		t.Fatal("expected error on non-2xx response")
	}
}

func TestCustomFromIsRespected(t *testing.T) {
	m := New(Config{APIKey: "k", Domain: "d.com", From: "Custom <c@d.com>"})
	if m.from != "Custom <c@d.com>" {
		t.Errorf("custom from overridden: %q", m.from)
	}
}
