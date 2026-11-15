package vpnclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBrowserLoginExchangesVerifiedSession(t *testing.T) {
	session := strings.Repeat("ab", 32)
	id, _, err := deriveHawkCredentials(session, "sessionToken")
	if err != nil {
		t.Fatal(err)
	}
	var challenge string
	previous := controlPlaneHTTPClient.Transport
	t.Cleanup(func() { SetControlPlaneTransport(previous) })
	SetControlPlaneTransport(identityTestTransport(func(req *http.Request) (*http.Response, error) {
		var result string
		switch req.URL.String() {
		case fxaAuthServer + "/recovery_email/status", fxaAuthServer + "/oauth/authorization":
			if got := req.Header.Get("Authorization"); got != "Bearer fxs_"+id {
				t.Fatal("expected the derived FxA session credential")
			}
			if req.Method == http.MethodGet {
				result = `{"verified":true}`
			} else {
				var payload map[string]string
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				challenge = payload["code_challenge"]
				if payload["scope"] != oauthScope || payload["code_challenge_method"] != "S256" {
					t.Fatal("expected the VPN scope and PKCE")
				}
				body, err := json.Marshal(map[string]string{"code": "test-code", "state": payload["state"]})
				if err != nil {
					t.Fatal(err)
				}
				result = string(body)
			}
		case fxaOAuthHost:
			var payload map[string]string
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256([]byte(payload["code_verifier"]))
			if payload["code"] != "test-code" || base64.RawURLEncoding.EncodeToString(hash[:]) != challenge {
				t.Fatal("authorization code or PKCE verifier did not match")
			}
			result = `{"access_token":"test-access","refresh_token":"test-refresh","expires_in":3600}`
		default:
			t.Fatalf("unexpected OAuth endpoint %s", req.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(result)), Header: make(http.Header)}, nil
	}))

	token, err := FxaBrowserToken(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "test-access" || token.RefreshToken != "test-refresh" {
		t.Fatal("expected both OAuth tokens")
	}
}
