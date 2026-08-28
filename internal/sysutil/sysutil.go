//go:build linux

// Package sysutil — общие системные утилиты: clamp, классификация ошибок, poll fd.
package sysutil

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Clamp — ограничить x в [lo,hi].
// Вход: x, lo, hi. Выход: значение в пределах.
func Clamp(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// IsWouldBlockErr — true для EAGAIN/EWOULDBLOCK.
// Вход: err. Выход: bool.
func IsWouldBlockErr(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}

// IsTempRecvErr — временные ошибки RX.
// Вход: err. Выход: true если ошибку можно переждать и продолжить.
func IsTempRecvErr(err error) bool {
	if err == nil {
		return false
	}
	if IsWouldBlockErr(err) || errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return true
		}
		return IsTempRecvErr(ne.Err)
	}
	var se *os.SyscallError
	if errors.As(err, &se) {
		return IsTempRecvErr(se.Err)
	}
	return false
}

// IsTempSendErr — временные ошибки TX.
// Вход: err. Выход: true если временная.
func IsTempSendErr(err error) bool {
	if err == nil {
		return false
	}
	if IsWouldBlockErr(err) || errors.Is(err, syscall.ENOBUFS) {
		return true
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return true
		}
		return IsTempSendErr(ne.Err)
	}
	var se *os.SyscallError
	if errors.As(err, &se) {
		return IsTempSendErr(se.Err)
	}
	return false
}

// WaitFD — дождаться события на fd c точностью до наносекунд.
// Вход: fd, events, timeout; timeout < 0 означает ждать без дедлайна. Выход: ошибка ОС или nil.
func WaitFD(fd int32, events int16, timeout time.Duration) error {
	pfd := []unix.PollFd{{Fd: fd, Events: events}}
	for {
		var tsp *unix.Timespec
		if timeout >= 0 {
			ts := unix.NsecToTimespec(timeout.Nanoseconds())
			tsp = &ts
		}
		_, err := unix.Ppoll(pfd, tsp, nil)
		if err == nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}
