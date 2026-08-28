//go:build linux

// Package udp — UDP listeners (SO_REUSEPORT), GSO/GRO, error-queue монитор.
package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"l3overlay/internal/peers"
	"l3overlay/internal/sysutil"
)

// State — UDP-сокет и служебное состояние для логов/прогрева.
type State struct {
	Conn   *net.UDPConn
	PC     *ipv4.PacketConn
	FD     int
	zerocp bool
	zcMin  int
	txGSO  atomic.Bool
	Gro    bool

	RcvSz int // фактический SO_RCVBUF
	SndSz int // фактический SO_SNDBUF

	shared    *shared
	closeOnce sync.Once
}

// shared — общее состояние нескольких reuseport listeners.
type shared struct {
	logMu   sync.Mutex
	lastLog map[string]time.Time

	logCool     time.Duration
	warmupUntil atomic.Value // time.Time
}

// Bundle — набор UDP listeners на одном адресе/порту.
type Bundle struct {
	Listeners []*State
	Primary   *State
	closeOnce sync.Once
}

// icmpErrInfo — разобранная запись error-queue: sock_extended_err + источник ICMP.
type icmpErrInfo struct {
	errno    syscall.Errno
	origin   uint8
	typ      uint8
	code     uint8
	offender string // IPv4 источника ICMP (SO_EE_OFFENDER)
}

// udpSegmentControlMessage — собрать cmsg для одного sendmsg с UDP_SEGMENT.
// Вход: oob, segmentSize. Выход: готовый OOB буфер.
func udpSegmentControlMessage(oob []byte, segmentSize int) []byte {
	if cap(oob) < unix.CmsgSpace(2) {
		oob = make([]byte, unix.CmsgSpace(2))
	} else {
		oob = oob[:unix.CmsgSpace(2)]
		clear(oob)
	}
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.IPPROTO_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):unix.CmsgLen(0)+2], uint16(segmentSize))
	return oob
}

// supportsUDPSegment — проверить, доступен ли UDP_SEGMENT на сокете.
// Вход: fd. Выход: true если getsockopt не вернул ошибку.
func supportsUDPSegment(fd int) bool {
	if fd <= 0 {
		return false
	}
	_, err := unix.GetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT)
	return err == nil
}

// shouldDisableUDPGSO — ошибки, после которых GSO лучше выключить и откатиться.
// Вход: err. Выход: true если дальнейшие GSO-send лучше отключить.
func shouldDisableUDPGSO(err error) bool {
	return errors.Is(err, syscall.EIO) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EMSGSIZE) ||
		errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOTSUP)
}

// newUDPState — обернуть UDP сокет, включить опции и собрать runtime state.
// Вход: conn, rcv, snd, zerocopy, zcMin, sh. Выход: *State или ошибка.
func newUDPState(conn *net.UDPConn, rcv, snd int, zerocopy bool, zcMin int, sh *shared) (*State, error) {
	// запросить размеры буферов от конфигурации
	_ = conn.SetReadBuffer(rcv)
	_ = conn.SetWriteBuffer(snd)

	pc := ipv4.NewPacketConn(conn)

	// сырой fd
	var fd int
	if sc, err := conn.SyscallConn(); err == nil {
		_ = sc.Control(func(f uintptr) { fd = int(f) })
	}

	u := &State{
		Conn:   conn,
		PC:     pc,
		FD:     fd,
		zerocp: false,
		zcMin:  zcMin,
		RcvSz:  rcv,
		SndSz:  snd,
		shared: sh,
	}

	// Пробуем обойти rmem_max/wmem_max, если процессу доступен FORCE-вариант.
	if fd > 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, rcv); err != nil {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcv)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, snd); err != nil {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, snd)
		}
	}

	// прочитать фактические SO_RCVBUF/SO_SNDBUF (ядро может масштабировать)
	if fd > 0 {
		if sz, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
			u.RcvSz = sz
		}
		if sz, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF); err == nil {
			u.SndSz = sz
		}
	}

	// включить IP_RECVERR для чтения ICMP ошибок
	if fd > 0 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
			slog.Warn("IP_RECVERR off", "err", err)
		}
	}

	if supportsUDPSegment(fd) {
		u.txGSO.Store(true)
		slog.Debug("udp gso on")
	}

	// включить UDP_GRO для коалесцированного приёма GSO-трафика; без поддержки ядром — обычный приём
	if fd > 0 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1); err != nil {
			slog.Debug("udp gro off", "err", err)
		} else {
			u.Gro = true
			slog.Debug("udp gro on")
		}
	}

	return u, nil
}

// listenUDP — открыть UDP listener, при необходимости с SO_REUSEPORT.
// Вход: listen, reusePort. Выход: *net.UDPConn или ошибка.
func listenUDP(listen string, reusePort bool) (*net.UDPConn, error) {
	if !reusePort {
		laddr, err := net.ResolveUDPAddr("udp4", listen)
		if err != nil {
			return nil, err
		}
		return net.ListenUDP("udp4", laddr)
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = err
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					sockErr = err
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", listen)
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("unexpected UDP listener type")
	}
	return conn, nil
}

// NewBundle — создать один или несколько reuseport-bound UDP listeners.
// Вход: listen, listenerCount, rcv, snd, reusePort, zerocopy, zcMin. Выход: *Bundle или ошибка.
func NewBundle(listen string, listenerCount, rcv, snd int, reusePort, zerocopy bool, zcMin int) (*Bundle, error) {
	sh := &shared{
		lastLog: make(map[string]time.Time),
		logCool: 5 * time.Second,
	}
	sh.warmupUntil.Store(time.Time{})
	bundle := &Bundle{Listeners: make([]*State, 0, listenerCount)}
	for i := 0; i < listenerCount; i++ {
		conn, err := listenUDP(listen, reusePort)
		if err != nil {
			bundle.Close()
			return nil, err
		}
		u, err := newUDPState(conn, rcv, snd, zerocopy, zcMin, sh)
		if err != nil {
			_ = conn.Close()
			bundle.Close()
			return nil, err
		}
		bundle.Listeners = append(bundle.Listeners, u)
	}
	if len(bundle.Listeners) == 0 {
		return nil, errors.New("no UDP listeners created")
	}
	bundle.Primary = bundle.Listeners[0]
	return bundle, nil
}

// Close — закрыть UDP listener.
// Вход: нет. Выход: нет.
func (u *State) Close() {
	u.closeOnce.Do(func() {
		_ = u.PC.Close()
		_ = u.Conn.Close()
	})
}

// TxGSOEnabled — текущее состояние runtime-поддержки UDP_SEGMENT на сокете.
// Вход: нет. Выход: true если TX может пытаться коалесцировать sendmsg.
func (u *State) TxGSOEnabled() bool {
	return u.txGSO.Load()
}

// DisableTxGSO — выключить GSO после ошибки пути/ядра и залогировать это один раз.
// Вход: err. Выход: нет.
func (u *State) DisableTxGSO(err error) {
	if u.txGSO.CompareAndSwap(true, false) {
		slog.Warn("udp gso off", "err", err)
	}
}

// ZeroCopy — текущее состояние zerocopy на сокете (путь отключён, всегда false).
// Вход: нет. Выход: bool.
func (u *State) ZeroCopy() bool {
	return u.zerocp
}

// Close — закрыть весь UDP bundle.
// Вход: нет. Выход: нет.
func (b *Bundle) Close() {
	b.closeOnce.Do(func() {
		for _, u := range b.Listeners {
			u.Close()
		}
	})
}

// SetWarmupUntil — установить дедлайн прогрева.
// Вход: t. Выход: нет.
func (u *State) SetWarmupUntil(t time.Time) {
	u.shared.warmupUntil.Store(t)
}

// InWarmup — true, пока не истёк дедлайн прогрева.
// Вход: now. Выход: bool.
func (u *State) InWarmup(now time.Time) bool {
	return now.Before(u.shared.warmupUntil.Load().(time.Time))
}

// Phase — текущая фаза: "warmup" или "tx".
// Вход: нет. Выход: строка фазы.
func (u *State) Phase() string {
	if u.InWarmup(time.Now()) {
		return "warmup"
	}
	return "tx"
}

// NotePeerUnavailable — троттлинг сообщений об ошибках доставки.
// Вход: ep, phase, reason, err. Выход: нет.
func (u *State) NotePeerUnavailable(ep, phase, reason string, err error) {
	now := time.Now()
	u.shared.logMu.Lock()
	last := u.shared.lastLog[ep]
	if now.Sub(last) < u.shared.logCool {
		u.shared.logMu.Unlock()
		return
	}
	u.shared.lastLog[ep] = now
	u.shared.logMu.Unlock()
	slog.Error("peer unavailable", "peer", ep, "phase", phase, "reason", reason, "err", err)
}

// WriteBatchMessages — отправить обычный UDP batch через WriteBatch.
// Вход: ctx, u, msgs. Выход: ошибка отправки или nil.
func WriteBatchMessages(ctx context.Context, u *State, msgs []ipv4.Message) error {
	for off := 0; off < len(msgs); {
		n, err := u.PC.WriteBatch(msgs[off:], 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("udp write batch: %w", err)
		}
		if n <= 0 {
			return errors.New("udp write batch wrote 0 messages")
		}
		off += n
	}
	return nil
}

// SendGSOSegments — отправить несколько inner-пакетов одним sendmsg с UDP_SEGMENT.
// Вход: ctx, u, bufs (готовые сегменты, >= 2), sock4, oob. Выход: ошибка отправки или nil.
func SendGSOSegments(ctx context.Context, u *State, bufs [][]byte, sock4 *unix.SockaddrInet4, oob []byte) error {
	if len(bufs) < 2 {
		return errors.New("udp gso batch requires at least 2 packets")
	}
	segSize := len(bufs[0])
	totalBytes := 0
	for i := range bufs {
		totalBytes += len(bufs[i])
	}
	n, err := unix.SendmsgBuffers(u.FD, bufs, udpSegmentControlMessage(oob, segSize), sock4, 0)
	if err != nil {
		if shouldDisableUDPGSO(err) {
			u.DisableTxGSO(err)
		}
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if n != totalBytes {
		return fmt.Errorf("short udp gso send: %d of %d", n, totalBytes)
	}
	return nil
}

// StartErrMonitor — дренаж error-queue: лог ICMP unreachable с адресом источника.
// Вход: ctx, pm (сопоставление источника с известными endpoint), tick. Выход: нет.
func (u *State) StartErrMonitor(ctx context.Context, pm *peers.Map, tick time.Duration) {
	if u.FD <= 0 {
		return
	}
	if tick <= 0 {
		tick = 10 * time.Millisecond
	}
	if tick > 200*time.Millisecond {
		tick = 200 * time.Millisecond
	}
	go func() {
		oob := make([]byte, 512)
		buf := make([]byte, 512)
		pfd := []unix.PollFd{{Fd: int32(u.FD), Events: unix.POLLERR}}
		timeoutMS := int(tick / time.Millisecond)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, _ = unix.Poll(pfd, timeoutMS)
			for {
				_, oobn, _, _, err := unix.Recvmsg(u.FD, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
				if sysutil.IsWouldBlockErr(err) {
					break
				}
				if err != nil {
					return
				}
				info, ok := parseExtendedErr(oob[:oobn])
				if !ok || info.origin != unix.SO_EE_ORIGIN_ICMP || info.typ != 3 {
					continue
				}
				ep := info.offender
				if key, found := pm.EndpointByIP(info.offender); found {
					ep = key
				}
				u.NotePeerUnavailable(ep, u.Phase(), "icmp_unreachable", info.errno)
			}
		}
	}()
}

// parseExtendedErr — извлечь sock_extended_err и адрес источника ошибки из oob MSG_ERRQUEUE.
// Вход: oob (прочитанные cmsg). Выход: icmpErrInfo, ok.
func parseExtendedErr(oob []byte) (icmpErrInfo, bool) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return icmpErrInfo{}, false
	}
	for i := range cmsgs {
		if cmsgs[i].Header.Level != unix.IPPROTO_IP || cmsgs[i].Header.Type != unix.IP_RECVERR {
			continue
		}
		if len(cmsgs[i].Data) < int(unsafe.Sizeof(unix.SockExtendedErr{})) {
			continue
		}
		ee := (*unix.SockExtendedErr)(unsafe.Pointer(&cmsgs[i].Data[0]))
		info := icmpErrInfo{
			errno:  syscall.Errno(ee.Errno),
			origin: ee.Origin,
			typ:    ee.Type,
			code:   ee.Code,
		}
		// SO_EE_OFFENDER: sockaddr сразу за sock_extended_err
		off := cmsgs[i].Data[unsafe.Sizeof(unix.SockExtendedErr{}):]
		if len(off) >= int(unsafe.Sizeof(unix.RawSockaddrInet4{})) {
			rsa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&off[0]))
			if rsa.Family == unix.AF_INET {
				info.offender = net.IPv4(rsa.Addr[0], rsa.Addr[1], rsa.Addr[2], rsa.Addr[3]).String()
			}
		}
		return info, true
	}
	return icmpErrInfo{}, false
}
