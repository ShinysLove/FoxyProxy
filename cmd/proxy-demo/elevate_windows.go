package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The elevated helper receives only a local port, a worker PID and event IDs.
// The parent watches the helper's process handle and requests a graceful stop.
type elevatedTUN struct {
	process, stop windows.Handle
	done          chan struct{}
}

type shellExecuteInfo struct {
	size, mask                  uint32
	window                      uintptr
	verb, file, args, directory *uint16
	show                        int32
	instance, idList            uintptr
	class                       *uint16
	classKey                    uintptr
	hotKey                      uint32
	icon                        uintptr
	process                     windows.Handle
}

func elevateDesktopTUN(ctx context.Context, port int) (*elevatedTUN, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(random[:])
	ready, err := windows.CreateEvent(nil, 1, 0, tunEventName(id, "-ready"))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(ready)
	stop, err := windows.CreateEvent(nil, 1, 0, tunEventName(id, "-stop"))
	if err != nil {
		return nil, err
	}
	process, err := launchElevatedTUN(port, id)
	if err != nil {
		windows.CloseHandle(stop)
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return nil, errors.New("Для режима «Весь ПК» подтвердите запрос Windows на права администратора.")
		}
		return nil, errors.New("Не удалось запустить виртуальный адаптер с правами администратора.")
	}
	tun := &elevatedTUN{process: process, stop: stop, done: make(chan struct{})}
	go func() {
		_, _ = windows.WaitForSingleObject(process, windows.INFINITE)
		close(tun.done)
	}()
	timer := time.NewTimer(24 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			tun.close()
			return nil, ctx.Err()
		case <-tun.done:
			tun.close()
			return nil, errors.New("Виртуальный адаптер Windows не запустился.")
		case <-timer.C:
			tun.close()
			return nil, errors.New("Виртуальный адаптер Windows не запустился вовремя.")
		case <-tick.C:
			if signaled, _ := windows.WaitForSingleObject(ready, 0); signaled == windows.WAIT_OBJECT_0 {
				return tun, nil
			}
		}
	}
}

func launchElevatedTUN(port int, id string) (windows.Handle, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{
		mask: 0x00000040 | 0x00000100 | 0x00000400, // NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI
		verb: windows.StringToUTF16Ptr("runas"),
		file: windows.StringToUTF16Ptr(exe),
		args: windows.StringToUTF16Ptr(fmt.Sprintf("-desktop-tun %d %d %s", os.Getpid(), port, id)),
	}
	info.size = uint32(unsafe.Sizeof(info))
	call := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
	if ok, _, err := call.Call(uintptr(unsafe.Pointer(&info))); ok == 0 {
		return 0, err
	}
	return info.process, nil
}

func (tun *elevatedTUN) close() {
	_ = windows.SetEvent(tun.stop)
	// The elevated helper also observes parent exit and owns the sing-box job.
	select {
	case <-tun.done:
		windows.CloseHandle(tun.process)
	case <-time.After(7 * time.Second):
		go func() {
			<-tun.done
			windows.CloseHandle(tun.process)
		}()
	}
	windows.CloseHandle(tun.stop)
}

func tunEventName(id, suffix string) *uint16 {
	return windows.StringToUTF16Ptr("Local\\FoxyProxy-" + id + suffix)
}

func runElevatedDesktopTUN(args []string) {
	if len(args) != 3 || !windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	parentPID, pidErr := strconv.ParseUint(args[0], 10, 32)
	port, portErr := strconv.ParseUint(args[1], 10, 16)
	id, idErr := hex.DecodeString(args[2])
	if pidErr != nil || parentPID == 0 || portErr != nil || port == 0 || idErr != nil || len(id) != 16 {
		return
	}
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(parentPID))
	if err != nil {
		return
	}
	defer windows.CloseHandle(parent)
	stop, err := windows.OpenEvent(windows.SYNCHRONIZE, false, tunEventName(args[2], "-stop"))
	if err != nil {
		return
	}
	defer windows.CloseHandle(stop)
	ready, err := windows.OpenEvent(0x0002, false, tunEventName(args[2], "-ready")) // EVENT_MODIFY_STATE
	if err != nil {
		return
	}
	defer windows.CloseHandle(ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return
	}
	defer windows.CloseHandle(finished)
	waitDone := make(chan struct{})
	defer func() {
		_ = windows.SetEvent(finished)
		<-waitDone
	}()
	go func() {
		defer close(waitDone)
		_, _ = windows.WaitForMultipleObjects([]windows.Handle{parent, stop, finished}, false, windows.INFINITE)
		cancel()
	}()
	tun, err := startDesktopTUN(ctx, int(port))
	if err != nil {
		return
	}
	defer tun.close()
	_ = windows.SetEvent(ready)
	select {
	case <-ctx.Done():
	case <-tun.done:
	}
}
