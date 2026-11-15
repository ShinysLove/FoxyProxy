package main

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	vpnclient "firefox-vpn-client"
)

func TestDesktopRestoresEncryptedSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.dat")
	if got := desktopRestoreSession(path); got != "reauthenticate" {
		t.Fatalf("without saved session got %q", got)
	}
	cache := desktopCache{
		Auth:   vpnclient.TokenResponse{AccessToken: "expired", RefreshToken: "test-refresh", ExpiresIn: 3600},
		Issued: time.Now().Add(-2 * time.Hour), Browser: true,
	}
	if err := saveDesktopCache(path, cache); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if got := desktopRestoreSession(path); got != "authenticated" {
		t.Fatalf("with renewable session got %q", got)
	}
	cache.Auth.RefreshToken = ""
	if err := saveDesktopCache(path, cache); err != nil {
		t.Fatal(err)
	}
	if got := desktopRestoreSession(path); got != "reauthenticate" {
		t.Fatalf("with expired session and no refresh token got %q", got)
	}
}

func TestDesktopMeasuresAndSelectsExactServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().String()
	candidates := []proxyCandidate{
		{CountryCode: "AA", CityCode: "aa", Addr: addr},
		{CountryCode: "BB", CityCode: "bb", Addr: addr},
	}
	servers := desktopMeasureServers(t.Context(), candidates)
	if len(servers) != 2 || servers[0].ID == servers[1].ID || servers[1].LatencyMs == nil {
		t.Fatalf("unexpected probe results: %+v", servers)
	}
	selected, err := desktopSelectCandidates(candidates, servers[1].ID)
	if err != nil || len(selected) != 1 || selected[0] != candidates[1] {
		t.Fatalf("unexpected selection %+v: %v", selected, err)
	}
	if _, err := desktopSelectCandidates(candidates, "removed"); err == nil {
		t.Fatal("removed server silently accepted")
	}
}
