package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed tun.json
var desktopTUNConfig string

type desktopTUN struct {
	process *os.Process
	job     windows.Handle
	done    chan struct{}
}

func startDesktopTUN(ctx context.Context, port int) (*desktopTUN, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, errors.New("Запустите Foxy Proxy от имени администратора для режима «Весь ПК».")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(filepath.Dir(executable), "tun", "sing-box.exe")
	if _, err := os.Stat(binary); err != nil {
		return nil, errors.New("Компонент sing-box отсутствует. Распакуйте весь архив приложения.")
	}
	// Keep Mozilla connections out of the TUN data path. The template uses
	// an exact process-path match for this worker and local DNS via the TUN.
	pathJSON, err := json.Marshal("(?i)^" + regexp.QuoteMeta(executable) + "$")
	if err != nil {
		return nil, err
	}
	config := fmt.Sprintf(desktopTUNConfig, port, pathJSON)
	ready := &tunOutput{ready: make(chan struct{})}
	cmd := exec.Command(binary, "run", "-c", "stdin", "-D", filepath.Dir(binary), "--disable-color")
	cmd.Stdin = bytes.NewBufferString(config)
	cmd.Stdout, cmd.Stderr = ready, ready
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	tun := &desktopTUN{process: cmd.Process, job: job, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(tun.done)
	}()
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, handle)
		windows.CloseHandle(handle)
	}
	if err != nil {
		tun.close()
		return nil, errors.New("Не удалось запустить виртуальный адаптер в этом сеансе Windows.")
	}
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case <-ready.ready:
		return tun, nil
	case <-tun.done:
		windows.CloseHandle(job)
		return nil, fmt.Errorf("Не удалось включить виртуальный адаптер Windows. %s", ready.lastLine())
	case <-ctx.Done():
		tun.close()
		return nil, ctx.Err()
	case <-timer.C:
		tun.close()
		return nil, errors.New("Виртуальный адаптер Windows не запустился вовремя.")
	}
}

type tunOutput struct {
	ready chan struct{}
	tail  []byte
}

func (out *tunOutput) Write(data []byte) (int, error) {
	out.tail = append(out.tail, data...)
	if bytes.Contains(out.tail, []byte("sing-box started (")) {
		select {
		case <-out.ready:
		default:
			close(out.ready)
		}
	}
	if len(out.tail) > 4096 {
		out.tail = append(out.tail[:0], out.tail[len(out.tail)-4096:]...)
	}
	return len(data), nil
}

func (out *tunOutput) lastLine() string {
	tail := bytes.TrimSpace(out.tail)
	return string(tail[bytes.LastIndexByte(tail, '\n')+1:])
}

func (tun *desktopTUN) close() {
	defer windows.CloseHandle(tun.job)
	select {
	case <-tun.done:
		return
	default:
	}
	// The child shares this worker's hidden console, in its own group.
	// CTRL_BREAK gives sing-box a chance to close the adapter and remove routes.
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(tun.process.Pid)); err == nil {
		timer := time.NewTimer(6 * time.Second)
		defer timer.Stop()
		select {
		case <-tun.done:
			return
		case <-timer.C:
		}
	}
	_ = tun.process.Kill()
	<-tun.done
}
