//go:build linux

package udp

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// buildGROCMsg — собрать oob с одним cmsg UDP_GRO для теста.
func buildGROCMsg(segSize int) []byte {
	oob := make([]byte, unix.CmsgSpace(2))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.IPPROTO_UDP
	hdr.Type = unix.UDP_GRO
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):unix.CmsgLen(0)+2], uint16(segSize))
	return oob
}

// TestParseExtendedErrLoopback — реальный error-queue: ICMP port unreachable с loopback.
// Проверяет разбор sock_extended_err и SO_EE_OFFENDER на живом ядре.
func TestParseExtendedErrLoopback(t *testing.T) {
	// свободный закрытый порт: занять и освободить
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("нет loopback UDP: %v", err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()

	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	fd := -1
	sc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}
	if err := sc.Control(func(f uintptr) { fd = int(f) }); err != nil {
		t.Fatalf("control: %v", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		t.Fatalf("IP_RECVERR: %v", err)
	}
	if _, err := c.Write([]byte{1}); err != nil {
		t.Fatalf("write: %v", err)
	}

	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR}}
	n, err := unix.Poll(pfd, 2000)
	if err != nil || n == 0 {
		t.Skipf("нет ошибки в error-queue за 2с (poll n=%d err=%v)", n, err)
	}

	buf := make([]byte, 512)
	oob := make([]byte, 512)
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE)
	if err != nil {
		t.Fatalf("recvmsg MSG_ERRQUEUE: %v", err)
	}
	info, ok := parseExtendedErr(oob[:oobn])
	if !ok {
		t.Fatal("parseExtendedErr не распознал запись error-queue")
	}
	if info.origin != unix.SO_EE_ORIGIN_ICMP {
		t.Fatalf("origin = %d, ожидалось SO_EE_ORIGIN_ICMP (%d)", info.origin, unix.SO_EE_ORIGIN_ICMP)
	}
	if info.typ != 3 || info.code != 3 {
		t.Fatalf("type/code = %d/%d, ожидалось 3/3 (port unreachable)", info.typ, info.code)
	}
	if info.errno != syscall.ECONNREFUSED {
		t.Fatalf("errno = %v, ожидалось ECONNREFUSED", info.errno)
	}
	if info.offender != "127.0.0.1" {
		t.Fatalf("offender = %q, ожидалось 127.0.0.1", info.offender)
	}
}

// TestParseExtendedErrGarbage — устойчивость разбора к пустому и битому oob.
func TestParseExtendedErrGarbage(t *testing.T) {
	if _, ok := parseExtendedErr(nil); ok {
		t.Fatal("nil oob распознан как error-queue")
	}
	if _, ok := parseExtendedErr([]byte{0xff, 0x01}); ok {
		t.Fatal("мусор распознан как error-queue")
	}
	if _, ok := parseExtendedErr(buildGROCMsg(1500)); ok {
		t.Fatal("UDP_GRO cmsg распознан как error-queue")
	}
}
