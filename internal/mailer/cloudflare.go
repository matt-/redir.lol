// Package mailer sends transactional email via Cloudflare's Email Sending
// REST API (https://developers.cloudflare.com/email-service/api/send-emails/rest-api/).
package mailer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Mailer sends a single email. Implemented by CloudflareMailer; small
// interface so auth handlers can be tested without hitting the network.
type Mailer interface {
	Send(to, subject, html, text string) error
}

type CloudflareMailer struct {
	AccountID string
	APIToken  string
	From      string
	FromName  string

	client *http.Client
}

func NewCloudflareMailer(accountID, apiToken, from, fromName string) *CloudflareMailer {
	return &CloudflareMailer{
		AccountID: accountID,
		APIToken:  apiToken,
		From:      from,
		FromName:  fromName,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (m *CloudflareMailer) Send(to, subject, html, text string) error {
	from := interface{}(m.From)
	if m.FromName != "" {
		from = map[string]string{"address": m.From, "name": m.FromName}
	}
	payload, err := json.Marshal(map[string]interface{}{
		"to":      to,
		"from":    from,
		"subject": subject,
		"html":    html,
		"text":    text,
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/email/sending/send", m.AccountID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("cloudflare email send failed: status %d: %s", resp.StatusCode, body)
	}
	return nil
}
