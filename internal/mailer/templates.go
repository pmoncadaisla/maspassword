package mailer

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

// cardTmpl is the shared card layout: light background, white card with the
// Sésamo header (orange mark + lowercase wordmark, ODS square design: no
// border radius, orange button with black bold text), content area, optional
// button and an automatic-message footer. All styles are inline for
// email-client compatibility (the door mark is a plain orange square: SVG is
// unreliable in email clients).
var cardTmpl = template.Must(template.New("card").Parse(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
</head>
<body style="margin:0;padding:0;background-color:#f6f6f6;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f6f6f6;padding:32px 12px;">
<tr><td align="center">
<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background-color:#ffffff;border:1px solid #dddddd;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
<tr><td style="padding:20px 32px;border-bottom:1px solid #dddddd;">
<span style="display:inline-block;width:16px;height:16px;background-color:#ff7900;vertical-align:-2px;"></span>&nbsp;<span style="font-size:20px;font-weight:bold;color:#000000;letter-spacing:-0.02em;">s&eacute;samo</span>
</td></tr>
<tr><td style="padding:28px 32px;color:#333333;font-size:15px;line-height:1.6;">
{{.Body}}
{{if .ButtonURL}}<p style="text-align:center;margin:28px 0 8px;">
<a href="{{.ButtonURL}}" style="display:inline-block;background-color:#ff7900;color:#000000;font-weight:bold;text-decoration:none;padding:12px 28px;">{{.ButtonLabel}}</a>
</p>{{end}}
</td></tr>
<tr><td style="padding:16px 32px;border-top:1px solid #dddddd;color:#999999;font-size:12px;text-align:center;">
Este es un mensaje autom&aacute;tico de S&eacute;samo, un producto MasOrange. No respondas a este correo.
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
`))

type cardData struct {
	Title       string
	Body        template.HTML
	ButtonURL   string
	ButtonLabel string
}

// welcomeBody greets a just-created account (first SSO sign-in). It is static
// HTML (no template data), but kept as a template for symmetry with the rest.
var welcomeBody = template.Must(template.New("welcome").Parse(
	`<p>Hola,</p>
<p>Tu cuenta de S&eacute;samo se acaba de crear con tu inicio de sesi&oacute;n de Google. Ya tienes tu caja fuerte personal para guardar contrase&ntilde;as, notas y m&aacute;s.</p>
<p>S&eacute;samo es un gestor de contrase&ntilde;as de conocimiento cero: todo se cifra en tu dispositivo con una <strong>contrase&ntilde;a maestra</strong> que solo t&uacute; conoces y que crear&aacute;s al entrar por primera vez. Guarda bien la <strong>clave de recuperaci&oacute;n</strong> que te daremos entonces: sin ella y sin tu contrase&ntilde;a maestra, nadie &mdash; ni siquiera nosotros &mdash; puede descifrar tus datos.</p>
<p>Si no has sido t&uacute;, puedes ignorar este correo: sin tu inicio de sesi&oacute;n de Google la cuenta no puede usarse.</p>`))

var inviteMemberBody = template.Must(template.New("invite_member").Parse(
	`<p>Hola,</p>
<p><strong>{{.Actor}}</strong> te ha a&ntilde;adido al equipo <strong>{{.Team}}</strong> en S&eacute;samo con el rol de <strong>{{.Role}}</strong>.</p>
<p>Ya puedes acceder a las contrase&ntilde;as compartidas con el equipo.</p>`))

var inviteAdminsBody = template.Must(template.New("invite_admins").Parse(
	`<p>Hola,</p>
<p><strong>{{.Actor}}</strong> ha a&ntilde;adido a <strong>{{.Member}}</strong> al equipo <strong>{{.Team}}</strong> con el rol de <strong>{{.Role}}</strong>.</p>
<p>Recibes este aviso por ser administrador del equipo.</p>`))

var promoteAdminsBody = template.Must(template.New("promote_admins").Parse(
	`<p>Hola,</p>
<p><strong>{{.Member}}</strong> ha sido ascendido a administrador del equipo <strong>{{.Team}}</strong> por <strong>{{.Actor}}</strong>.</p>`))

func renderBody(t *template.Template, data any) (template.HTML, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rendering email body: %w", err)
	}
	return template.HTML(buf.String()), nil
}

func renderCard(d cardData) (string, error) {
	var buf bytes.Buffer
	if err := cardTmpl.Execute(&buf, d); err != nil {
		return "", fmt.Errorf("rendering email card: %w", err)
	}
	return buf.String(), nil
}

// renderTextCard builds the plain-text alternative of the card layout.
// Sending multipart (html+text) instead of HTML-only lowers the spam score.
func renderTextCard(body, buttonURL, buttonLabel string) string {
	var b strings.Builder
	b.WriteString("Sésamo\n\n")
	b.WriteString(body)
	if buttonURL != "" {
		b.WriteString(fmt.Sprintf("\n%s: %s\n", buttonLabel, buttonURL))
	}
	b.WriteString("\n--\nEste es un mensaje automático de Sésamo, un producto MasOrange. No respondas a este correo.\n")
	return b.String()
}

// RenderWelcome builds the email sent when an account is created on first
// SSO sign-in. baseURL, when non-empty, adds a button linking to the app.
func RenderWelcome(baseURL string) (subject, html, text string, err error) {
	subject = "Te damos la bienvenida a Sésamo"
	body, err := renderBody(welcomeBody, nil)
	if err != nil {
		return "", "", "", err
	}
	html, err = renderCard(cardData{Title: subject, Body: body, ButtonURL: baseURL, ButtonLabel: "Abrir Sésamo"})
	if err != nil {
		return "", "", "", err
	}
	text = renderTextCard(
		"Hola,\n\nTu cuenta de Sésamo se acaba de crear con tu inicio de sesión de Google. Ya tienes tu caja fuerte personal para guardar contraseñas, notas y más.\n\nSésamo es un gestor de contraseñas de conocimiento cero: todo se cifra en tu dispositivo con una contraseña maestra que solo tú conoces y que crearás al entrar por primera vez. Guarda bien la clave de recuperación que te daremos entonces: sin ella y sin tu contraseña maestra, nadie — ni siquiera nosotros — puede descifrar tus datos.\n\nSi no has sido tú, puedes ignorar este correo: sin tu inicio de sesión de Google la cuenta no puede usarse.\n",
		baseURL, "Abrir Sésamo")
	return subject, html, text, nil
}

// RenderInviteMember builds the email sent to a user added to a team.
// baseURL, when non-empty, adds a button linking to the app.
func RenderInviteMember(team, actor, role, baseURL string) (subject, html, text string, err error) {
	subject = fmt.Sprintf("Te han añadido al equipo %s en Sésamo", team)
	body, err := renderBody(inviteMemberBody, map[string]string{"Team": team, "Actor": actor, "Role": role})
	if err != nil {
		return "", "", "", err
	}
	html, err = renderCard(cardData{Title: subject, Body: body, ButtonURL: baseURL, ButtonLabel: "Abrir Sésamo"})
	if err != nil {
		return "", "", "", err
	}
	text = renderTextCard(fmt.Sprintf(
		"Hola,\n\n%s te ha añadido al equipo %s en Sésamo con el rol de %s.\n\nYa puedes acceder a las contraseñas compartidas con el equipo.\n",
		actor, team, role), baseURL, "Abrir Sésamo")
	return subject, html, text, nil
}

// RenderInviteAdmins builds the email sent to team admins when a member is added.
func RenderInviteAdmins(team, actor, member, role string) (subject, html, text string, err error) {
	subject = fmt.Sprintf("Nuevo miembro en el equipo %s", team)
	body, err := renderBody(inviteAdminsBody, map[string]string{"Team": team, "Actor": actor, "Member": member, "Role": role})
	if err != nil {
		return "", "", "", err
	}
	html, err = renderCard(cardData{Title: subject, Body: body})
	if err != nil {
		return "", "", "", err
	}
	text = renderTextCard(fmt.Sprintf(
		"Hola,\n\n%s ha añadido a %s al equipo %s con el rol de %s.\n\nRecibes este aviso por ser administrador del equipo.\n",
		actor, member, team, role), "", "")
	return subject, html, text, nil
}

// RenderPromoteAdmins builds the email sent to team admins and the promoted
// user when a member is promoted to admin.
func RenderPromoteAdmins(team, actor, member string) (subject, html, text string, err error) {
	subject = fmt.Sprintf("%s ahora es administrador de %s", member, team)
	body, err := renderBody(promoteAdminsBody, map[string]string{"Team": team, "Actor": actor, "Member": member})
	if err != nil {
		return "", "", "", err
	}
	html, err = renderCard(cardData{Title: subject, Body: body})
	if err != nil {
		return "", "", "", err
	}
	text = renderTextCard(fmt.Sprintf(
		"Hola,\n\n%s ha sido ascendido a administrador del equipo %s por %s.\n",
		member, team, actor), "", "")
	return subject, html, text, nil
}
