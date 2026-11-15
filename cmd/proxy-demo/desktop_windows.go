package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	vpnclient "firefox-vpn-client"
	"golang.org/x/sys/windows"
)

type desktopRequest struct {
	Mode, Session, Server string
}

type desktopEvent struct {
	Type          string
	Message       string          `json:",omitempty"`
	Address       string          `json:",omitempty"`
	SentBytes     uint64          `json:",omitempty"`
	ReceivedBytes uint64          `json:",omitempty"`
	Server        string          `json:",omitempty"`
	Servers       []desktopServer `json:",omitempty"`
}

type desktopCache struct {
	Auth    vpnclient.TokenResponse
	Issued  time.Time
	Browser bool
}

const desktopSOCKS = "127.0.0.1:1080"

func runDesktopCommand() bool {
	if len(os.Args) > 1 && os.Args[1] == "-desktop-tun" {
		runElevatedDesktopTUN(os.Args[2:])
		return true
	}
	if len(os.Args) != 2 || os.Args[1] != "-desktop-worker" {
		return false
	}
	input := json.NewDecoder(os.Stdin)
	output := json.NewEncoder(os.Stdout)
	emit := func(event desktopEvent) { _ = output.Encode(event) }
	if err := desktopConnect(input, emit); err != nil && !errors.Is(err, io.EOF) {
		emit(desktopEvent{Type: "error", Message: err.Error()})
	}
	return true
}

func desktopConnect(input *json.Decoder, emit func(desktopEvent)) error {
	var request desktopRequest
	if err := input.Decode(&request); err != nil {
		return err
	}
	if request.Mode == "restore" {
		path, err := desktopCachePath()
		if err != nil {
			return err
		}
		emit(desktopEvent{Type: desktopRestoreSession(path)})
		return nil
	}
	if request.Mode == "servers" {
		ctx, cancel := desktopRequestContext(input)
		defer cancel()
		candidates, err := desktopCandidates(ctx)
		if err != nil {
			return err
		}
		emit(desktopEvent{Type: "servers", Servers: desktopMeasureServers(ctx, candidates)})
		return nil
	}
	if request.Mode != "tun" && request.Mode != "socks" && request.Mode != "login" {
		return errors.New("Выберите режим подключения.")
	}
	lockName := windows.StringToUTF16Ptr("Local\\FoxyProxyConnection")
	lock, err := windows.CreateMutex(nil, false, lockName)
	if lock != 0 {
		defer windows.CloseHandle(lock)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return errors.New("Foxy Proxy уже подключается или работает в другом окне.")
	}
	if err != nil {
		return errors.New("Не удалось подготовить подключение Windows.")
	}
	// Closing the input pipe cancels startup and disconnects a running worker.
	ctx, cancel := desktopRequestContext(input)
	defer cancel()
	auth, err := desktopAuthenticate(ctx, emit, request)
	if err != nil || request.Mode == "login" {
		return err
	}

	listen := desktopSOCKS
	if request.Mode == "tun" {
		listen = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("Не удалось открыть SOCKS5 на %s. Проверьте, свободен ли порт.", listen)
	}
	defer listener.Close()

	emit(desktopEvent{Type: "progress", Message: "Подключение к прокси Mozilla…"})
	controller, candidate, err := desktopProxyController(ctx, auth, request.Server)
	if err != nil {
		return err
	}
	defer controller.Close()
	go controller.runRenewalLoop()

	server := newSocksServer(controller, defaultHandshakeTimeout, defaultIdleTimeout, defaultMaxConnections)
	traffic := &socksTraffic{}
	server.traffic = traffic
	reportTraffic := func() {
		emit(desktopEvent{Type: "traffic", SentBytes: traffic.sent.Load(), ReceivedBytes: traffic.received.Load()})
	}
	go func() {
		defer cancel()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.handleConn(conn)
		}
	}()

	var tunDone <-chan struct{}
	if request.Mode == "tun" {
		emit(desktopEvent{Type: "progress", Message: "Запуск виртуального адаптера…"})
		tun, err := elevateDesktopTUN(ctx, listener.Addr().(*net.TCPAddr).Port)
		if err != nil {
			return err
		}
		defer tun.close()
		tunDone = tun.done
		emit(desktopEvent{Type: "connected", Server: desktopServerLabel(candidate)})
	} else {
		emit(desktopEvent{Type: "connected", Address: listener.Addr().String(), Server: desktopServerLabel(candidate)})
	}
	defer reportTraffic()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tunDone:
			return errors.New("Виртуальный адаптер остановился. Подключитесь снова.")
		case <-ticker.C:
			reportTraffic()
		}
	}
}

func desktopRequestContext(input *json.Decoder) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		var stop desktopRequest
		_ = input.Decode(&stop)
		cancel()
	}()
	return ctx, cancel
}

func desktopProxyController(ctx context.Context, auth *runtimeAuth, selected string) (*proxyController, proxyCandidate, error) {
	const guardian = vpnclient.GuardianEndpointDefault
	candidates, err := desktopCandidates(ctx)
	if err != nil {
		return nil, proxyCandidate{}, err
	}
	candidates, err = desktopSelectCandidates(candidates, selected)
	if err != nil {
		return nil, proxyCandidate{}, err
	}
	pass, auth, err := acquireInitialPass(guardian, auth, nil)
	switch {
	case errors.Is(err, vpnclient.ErrTokenInvalid):
		return nil, proxyCandidate{}, errors.New("Mozilla не разрешила прокси для этого аккаунта. Проверьте доступ к Firefox VPN.")
	case errors.Is(err, vpnclient.ErrQuotaExceeded) || isQuotaExhausted(pass):
		return nil, proxyCandidate{}, errors.New("Лимит трафика Mozilla исчерпан.")
	case err != nil:
		return nil, proxyCandidate{}, errors.New("Не удалось получить доступ к прокси Mozilla. Попробуйте снова.")
	}
	config := proxyControllerConfig{Guardian: guardian, Timeout: 8 * time.Second, Auth: auth, Pass: pass}
	// Try several locations because the published list can contain unreachable servers.
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, proxyCandidate{}, err
		}
		config.ProxyURL, err = normalizeProxyURL(candidate.Addr)
		if err != nil {
			continue
		}
		controller, err := newProxyController(config)
		if err == nil {
			return controller, candidate, nil
		}
	}
	if selected != "" {
		return nil, proxyCandidate{}, errors.New("Выбранный сервер не ответил. Выберите другой сервер или обновите задержку.")
	}
	return nil, proxyCandidate{}, errors.New("Серверы прокси Mozilla не ответили. Попробуйте подключиться ещё раз.")
}

func desktopRestoreSession(path string) string {
	if cached, err := loadDesktopCache(path); err == nil &&
		(cached.Auth.RefreshToken != "" || (&runtimeAuth{Token: &cached.Auth, ObtainedAt: cached.Issued}).accessTokenValid(time.Now())) {
		return "authenticated"
	}
	return "reauthenticate"
}
func desktopAuthenticate(ctx context.Context, emit func(desktopEvent), request desktopRequest) (*runtimeAuth, error) {
	path, err := desktopCachePath()
	if err != nil {
		return nil, err
	}
	browser := true
	save := func(token *vpnclient.TokenResponse) error {
		return saveDesktopCache(path, desktopCache{Auth: *token, Issued: time.Now(), Browser: browser})
	}
	if request.Mode == "login" {
		emit(desktopEvent{Type: "progress", Message: "Ожидаем подтверждения от Mozilla…"})
		loginCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		token, err := vpnclient.FxaBrowserToken(loginCtx, request.Session)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, errors.New("Время подтверждения истекло. Откройте окно входа снова.")
			}
			return nil, errors.New("Mozilla не завершила вход. Проверьте подтверждение аккаунта и попробуйте снова.")
		}
		if err := save(token); err != nil {
			return nil, errors.New("Не удалось сохранить защищённую сессию Windows.")
		}
		emit(desktopEvent{Type: "authenticated"})
		vpnclient.FxaEndBrowserSession(loginCtx, request.Session)
		return nil, nil
	}
	cached, err := loadDesktopCache(path)
	if err != nil || (cached.Auth.AccessToken == "" && cached.Auth.RefreshToken == "") {
		emit(desktopEvent{Type: "reauthenticate"})
		return nil, errors.New("Войдите в аккаунт Mozilla.")
	}
	browser = cached.Browser
	auth := &runtimeAuth{Token: &cached.Auth, ObtainedAt: cached.Issued, saveToken: save}
	if browser {
		auth.refreshToken = vpnclient.FxaBrowserRefresh
	}
	if auth.accessTokenValid(time.Now()) {
		return auth, nil
	}
	if auth.Token.RefreshToken == "" {
		emit(desktopEvent{Type: "reauthenticate"})
		return nil, errors.New("Срок действия входа истёк. Войдите в Mozilla снова.")
	}
	emit(desktopEvent{Type: "progress", Message: "Обновляем сессию Mozilla…"})
	refreshed, err := refreshRuntimeAuth(auth)
	if err != nil {
		if vpnclient.FxaBrowserSessionRejected(err) {
			_ = os.Remove(path)
			emit(desktopEvent{Type: "reauthenticate"})
			return nil, errors.New("Mozilla отклонила сохранённую сессию. Войдите снова.")
		}
		return nil, errors.New("Не удалось обновить сессию. Проверьте интернет и попробуйте снова.")
	}
	return refreshed, nil
}

func desktopCachePath() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil || root == "" {
		return "", errors.New("Папка профиля Windows недоступна.")
	}
	dir := filepath.Join(root, "FoxyProxy")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", errors.New("Не удалось открыть папку профиля Foxy Proxy.")
	}
	return filepath.Join(dir, "session.dat"), nil
}

func loadDesktopCache(path string) (desktopCache, error) {
	var cached desktopCache
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return cached, err
	}
	decoded, err := desktopDPAPI(encrypted, false)
	if err != nil {
		return cached, err
	}
	defer clear(decoded)
	err = json.Unmarshal(decoded, &cached)
	return cached, err
}

func saveDesktopCache(path string, cached desktopCache) error {
	raw, err := json.Marshal(cached)
	if err != nil {
		return err
	}
	defer clear(raw)
	encrypted, err := desktopDPAPI(raw, true)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "session-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	_, writeErr := temp.Write(encrypted)
	if err := errors.Join(writeErr, temp.Close()); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temp.Name())
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func desktopDPAPI(data []byte, encrypt bool) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(data)), Data: unsafe.SliceData(data)}
	var out windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	bytes := unsafe.Slice(out.Data, out.Size)
	defer clear(bytes)
	return append([]byte(nil), bytes...), nil
}
