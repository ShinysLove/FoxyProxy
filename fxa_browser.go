package vpnclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const fxaOAuthHost = "https://oauth.accounts.firefox.com/v1/token"

// FxaBrowserToken exchanges a session received from Firefox Accounts for
// VPN-scoped OAuth tokens via the FoxyVPN authorization-code flow.
func FxaBrowserToken(ctx context.Context, session string) (*TokenResponse, error) {
	if raw, err := hex.DecodeString(session); err != nil || len(raw) != 32 {
		return nil, errors.New("invalid FxA session token")
	}
	for {
		var status struct{ Verified bool }
		if err := fxaBrowserRequest(ctx, http.MethodGet, fxaAuthServer+"/recovery_email/status", session, nil, &status); err != nil {
			return nil, err
		}
		if status.Verified {
			break
		}
		if err := waitForBrowserVerification(ctx); err != nil {
			return nil, err
		}
	}

	for {
		token, err := fxaBrowserExchange(ctx, session)
		if err == nil {
			return token, nil
		}
		var apiErr *fxaAPIError
		if !errors.As(err, &apiErr) || (apiErr.Errno != 104 && apiErr.Errno != 138) {
			return nil, err
		}
		if err := waitForBrowserVerification(ctx); err != nil {
			return nil, err
		}
	}
}

// FxaEndBrowserSession releases the temporary sign-in session after the
// application has persisted its OAuth tokens.
func FxaEndBrowserSession(ctx context.Context, session string) {
	cleanup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = fxaBrowserRequest(cleanup, http.MethodPost, fxaAuthServer+"/session/destroy", session, map[string]string{}, nil)
}

func waitForBrowserVerification(ctx context.Context) error {
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func fxaBrowserExchange(ctx context.Context, session string) (*TokenResponse, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	request := map[string]string{
		"client_id": firefoxClientID, "response_type": "code", "access_type": "offline",
		"scope": oauthScope, "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
	}
	var authorization struct{ Code, State string }
	if err := fxaBrowserRequest(ctx, http.MethodPost, fxaAuthServer+"/oauth/authorization", session, request, &authorization); err != nil {
		return nil, err
	}
	if authorization.Code == "" || authorization.State != state {
		return nil, errors.New("invalid FxA authorization response")
	}
	return fxaBrowserGrant(ctx, map[string]string{
		"client_id": firefoxClientID, "grant_type": "authorization_code",
		"code": authorization.Code, "code_verifier": verifier,
	})
}

func FxaBrowserRefresh(ctx context.Context, refresh string) (*TokenResponse, error) {
	token, err := fxaBrowserGrant(ctx, map[string]string{
		"client_id": firefoxClientID, "grant_type": "refresh_token",
		"refresh_token": refresh, "scope": oauthScope,
	})
	if err == nil && token.RefreshToken == "" {
		token.RefreshToken = refresh
	}
	return token, err
}

func FxaBrowserSessionRejected(err error) bool {
	var apiErr *fxaAPIError
	return errors.As(err, &apiErr) && (apiErr.Status == 400 || apiErr.Status == 401 || apiErr.Status == 403)
}

func fxaBrowserGrant(ctx context.Context, request map[string]string) (*TokenResponse, error) {
	var token TokenResponse
	err := fxaBrowserRequest(ctx, http.MethodPost, fxaOAuthHost, "", request, &token)
	var apiErr *fxaAPIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotAcceptable {
		token = TokenResponse{}
		err = fxaBrowserRequest(ctx, http.MethodPost, fxaAuthServer+"/oauth/token", "", request, &token)
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, errors.New("FxA did not return an access token")
	}
	if token.ExpiresIn <= 0 {
		token.ExpiresIn = 24 * 60 * 60
	}
	return &token, nil
}

func fxaBrowserRequest(ctx context.Context, method, endpoint, session string, data map[string]string, result any) error {
	var payload []byte
	if data != nil {
		var err error
		payload, err = json.Marshal(data)
		if err != nil {
			return err
		}
	}
	build := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		applyFxAHeaders(req)
		if data != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if session != "" {
			if !strings.HasPrefix(endpoint, fxaAuthServer+"/") {
				return nil, errors.New("unexpected FxA session endpoint")
			}
			id, _, err := deriveHawkCredentials(session, "sessionToken")
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer fxs_"+id)
		}
		return req, nil
	}
	var response *http.Response
	var err error
	if endpoint == fxaOAuthHost || method == http.MethodGet || result == nil {
		req, buildErr := build()
		if buildErr != nil {
			return buildErr
		}
		response, err = doControlPlane(req)
	} else {
		response, err = fxaDo(ctx, build)
	}
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return newFxaAPIError(response.StatusCode, []byte(readErrorBody(response.Body)))
	}
	if result == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 256*1024)).Decode(result); err != nil {
		return fmt.Errorf("decoding FxA response: %w", err)
	}
	return nil
}
