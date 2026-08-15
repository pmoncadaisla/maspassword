// Package mailer sends transactional HTML emails through the Mailgun HTTP API
// using only the standard library. When no API key or domain is configured the
// mailer is disabled and Send becomes a logging no-op, so the rest of the
// application works unchanged without credentials.
package mailer

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds the Mailgun settings.
type Config struct {
	APIKey     string
	Domain     string
	From       string // defaults to "Sésamo <noreply@{Domain}>"
	EU         bool   // use the EU API endpoint
	AppBaseURL string // base URL of the web app, used for links in emails
}

type Mailer struct {
	apiKey     string
	domain     string
	from       string
	appBaseURL string
	apiBase    string
	client     *http.Client
}

func New(cfg Config) *Mailer {
	apiBase := "https://api.mailgun.net"
	if cfg.EU {
		apiBase = "https://api.eu.mailgun.net"
	}
	from := cfg.From
	if from == "" && cfg.Domain != "" {
		from = fmt.Sprintf("Sésamo <noreply@%s>", cfg.Domain)
	}
	return &Mailer{
		apiKey:     cfg.APIKey,
		domain:     cfg.Domain,
		from:       from,
		appBaseURL: cfg.AppBaseURL,
		apiBase:    apiBase,
		client:     &http.Client{Timeout: 15 * time.Second},
	}
}

// Enabled reports whether the mailer has credentials to actually send email.
// It is nil-safe so a nil *Mailer behaves as disabled.
func (m *Mailer) Enabled() bool {
	return m != nil && m.apiKey != "" && m.domain != ""
}

// Send delivers a single email to one recipient through Mailgun. A non-empty
// text becomes the plain-text alternative of the HTML part (multipart emails
// score better with spam filters). When the mailer is disabled it logs and
// returns nil.
func (m *Mailer) Send(ctx context.Context, to, subject, html, text string) error {
	if !m.Enabled() {
		log.Printf("mailer disabled, skipping email: %s", subject)
		return nil
	}

	form := url.Values{}
	form.Set("from", m.from)
	form.Set("to", to)
	form.Set("subject", subject)
	form.Set("html", html)
	if text != "" {
		form.Set("text", text)
	}

	endpoint := fmt.Sprintf("%s/v3/%s/messages", m.apiBase, m.domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("building mailgun request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("api", m.apiKey)

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("mailgun returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// SendMemberInvited emails a user who has just been added to a team.
func (m *Mailer) SendMemberInvited(ctx context.Context, to, team, actor, role string) error {
	base := ""
	if m != nil {
		base = m.appBaseURL
	}
	subject, html, text, err := RenderInviteMember(team, actor, role, base)
	if err != nil {
		return err
	}
	return m.Send(ctx, to, subject, html, text)
}

// SendAdminsMemberAdded notifies a team admin that a member was added.
func (m *Mailer) SendAdminsMemberAdded(ctx context.Context, to, team, actor, member, role string) error {
	subject, html, text, err := RenderInviteAdmins(team, actor, member, role)
	if err != nil {
		return err
	}
	return m.Send(ctx, to, subject, html, text)
}

// SendAdminsPromoted notifies admins (and the promoted user) of a promotion.
func (m *Mailer) SendAdminsPromoted(ctx context.Context, to, team, actor, member string) error {
	subject, html, text, err := RenderPromoteAdmins(team, actor, member)
	if err != nil {
		return err
	}
	return m.Send(ctx, to, subject, html, text)
}
