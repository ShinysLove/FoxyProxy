package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	vpnclient "firefox-vpn-client"
)

type desktopServer struct {
	ID        string
	Label     string
	LatencyMs *int64
}

func desktopServerID(candidate proxyCandidate) string {
	return candidate.CountryCode + "/" + candidate.CityCode + "/" + candidate.Addr
}

func desktopServerLabel(candidate proxyCandidate) string {
	place := candidate.CountryNameOrUnknown()
	if candidate.CityName != "" && !strings.EqualFold(candidate.CityName, place) {
		place += ", " + candidate.CityName
	}
	return place + " · " + candidate.Addr
}

func desktopCandidates(ctx context.Context) ([]proxyCandidate, error) {
	ctx, cancel := context.WithTimeout(ctx, apiRequestTimeout)
	defer cancel()
	countries, err := vpnclient.FetchServerList(ctx)
	if err != nil {
		return nil, errors.New("Список серверов Mozilla недоступен. Проверьте интернет-соединение.")
	}
	var candidates []proxyCandidate
	seen := make(map[string]bool)
	for _, candidate := range connectProxyCandidates(countries) {
		id := desktopServerID(candidate)
		if seen[id] {
			continue
		}
		seen[id] = true
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return nil, errors.New("Mozilla не вернула серверы прокси.")
	}
	return candidates, nil
}

func desktopSelectCandidates(candidates []proxyCandidate, selected string) ([]proxyCandidate, error) {
	if selected == "" {
		return candidates[:min(len(candidates), 6)], nil
	}
	for _, candidate := range candidates {
		if desktopServerID(candidate) == selected {
			return []proxyCandidate{candidate}, nil
		}
	}
	return nil, errors.New("Выбранного сервера больше нет в списке Mozilla. Обновите список и выберите сервер.")
}

func desktopMeasureServers(ctx context.Context, candidates []proxyCandidate) []desktopServer {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	results := make([]desktopServer, len(candidates))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(12, len(candidates)) {
		workers.Go(func() {
			for index := range jobs {
				candidate := candidates[index]
				result := desktopServer{ID: desktopServerID(candidate), Label: desktopServerLabel(candidate)}
				started := time.Now()
				if conn, err := dialer.DialContext(ctx, "tcp", candidate.Addr); err == nil {
					ms := max(int64(1), time.Since(started).Round(time.Millisecond).Milliseconds())
					result.LatencyMs = &ms
					_ = conn.Close()
				}
				results[index] = result
			}
		})
	}
	for index := range candidates {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	return results
}
