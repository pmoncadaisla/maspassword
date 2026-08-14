package mailer

import (
	"bytes"
	"fmt"
	"html/template"
)

// cardTmpl is the shared card layout: light background, white card with a
// MasPassword header, content area, optional button and an automatic-message
// footer. All styles are inline for email-client compatibility.
var cardTmpl = template.Must(template.New("card").Parse(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
</head>
<body style="margin:0;padding:0;background-color:#f2f4f8;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f2f4f8;padding:32px 12px;">
<tr><td align="center">
<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background-color:#ffffff;border-radius:10px;border:1px solid #e3e8ef;font-family:Arial,Helvetica,sans-serif;">
<tr><td style="padding:20px 32px;border-bottom:1px solid #e3e8ef;">
<span style="font-size:20px;font-weight:bold;color:#111827;">Mas<span style="color:#ff7900;">Password</span></span>
</td></tr>
<tr><td style="padding:28px 32px;color:#1f2933;font-size:15px;line-height:1.6;">
{{.Body}}
{{if .ButtonURL}}<p style="text-align:center;margin:28px 0 8px;">
<a href="{{.ButtonURL}}" style="display:inline-block;background-color:#ff7900;color:#ffffff;font-weight:bold;text-decoration:none;padding:12px 28px;border-radius:8px;">{{.ButtonLabel}}</a>
</p>{{end}}
</td></tr>
<tr><td style="padding:16px 32px;border-top:1px solid #e3e8ef;color:#9aa5b1;font-size:12px;text-align:center;">
Este es un mensaje autom&aacute;tico de MasPassword. No respondas a este correo.
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

var inviteMemberBody = template.Must(template.New("invite_member").Parse(
	`<p>Hola,</p>
<p><strong>{{.Actor}}</strong> te ha a&ntilde;adido al equipo <strong>{{.Team}}</strong> en MasPassword con el rol de <strong>{{.Role}}</strong>.</p>
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

// RenderInviteMember builds the email sent to a user added to a team.
// baseURL, when non-empty, adds a button linking to the app.
func RenderInviteMember(team, actor, role, baseURL string) (subject, html string, err error) {
	subject = fmt.Sprintf("Te han añadido al equipo %s en MasPassword", team)
	body, err := renderBody(inviteMemberBody, map[string]string{"Team": team, "Actor": actor, "Role": role})
	if err != nil {
		return "", "", err
	}
	html, err = renderCard(cardData{Title: subject, Body: body, ButtonURL: baseURL, ButtonLabel: "Abrir MasPassword"})
	if err != nil {
		return "", "", err
	}
	return subject, html, nil
}

// RenderInviteAdmins builds the email sent to team admins when a member is added.
func RenderInviteAdmins(team, actor, member, role string) (subject, html string, err error) {
	subject = fmt.Sprintf("Nuevo miembro en el equipo %s", team)
	body, err := renderBody(inviteAdminsBody, map[string]string{"Team": team, "Actor": actor, "Member": member, "Role": role})
	if err != nil {
		return "", "", err
	}
	html, err = renderCard(cardData{Title: subject, Body: body})
	if err != nil {
		return "", "", err
	}
	return subject, html, nil
}

// RenderPromoteAdmins builds the email sent to team admins and the promoted
// user when a member is promoted to admin.
func RenderPromoteAdmins(team, actor, member string) (subject, html string, err error) {
	subject = fmt.Sprintf("%s ahora es administrador de %s", member, team)
	body, err := renderBody(promoteAdminsBody, map[string]string{"Team": team, "Actor": actor, "Member": member})
	if err != nil {
		return "", "", err
	}
	html, err = renderCard(cardData{Title: subject, Body: body})
	if err != nil {
		return "", "", err
	}
	return subject, html, nil
}
