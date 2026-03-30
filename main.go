//go:build linux

// L3-оверлей через TUN и UDP. IPv4-only. Без шифрования.
// Без virtio-net vnet_hdr: читаем и пишем в TUN чистые L3-пакеты (IFF_NO_PI).
//
// Производительность:
// - RX: ipv4.PacketConn.ReadBatch → запись в TUN (L3).
// - TX: чтение из TUN (L3) → отправка UDP: копирующий батч WriteBatch или GSO sendmsg.
//
// Логи недоступности пира: warmup и tx, троттлинг 5с/peer.

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/BurntSushi/toml"
	netlink "github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

//
// ======================= Конфиг и типы =======================
//

// Config — конфигурация сервиса.
// Вход: TOML. Выход: валидированная структура с дефолтами.
type Config struct {
	Tun struct {
		Name       string   `toml:"name"`        // имя TUN; "" → "tun0"
		Queues     int      `toml:"queues"`      // число очередей TUN; 0 → 1
		Addr       string   `toml:"addr"`        // IPv4 CIDR для TUN, напр. "10.10.0.1/24"
		LinkMTU    int      `toml:"link_mtu"`    // MTU интерфейса; 0 → 9000
		AddRoute   bool     `toml:"add_route"`   // добавить маршрут своей подсети на TUN
		GrayRoutes []string `toml:"gray_routes"` // доп. IPv4 CIDR, направлять в TUN
		MTU        int      `toml:"mtu"`         // целевой MTU inner; 0 → 9000
	} `toml:"tun"`
	Transport struct {
		Listen       string `toml:"listen"`          // UDP bind "ip:port"; "" → "0.0.0.0:5555"
		Listeners    int    `toml:"listeners"`       // число UDP listeners на одном listen; 0 → 1
		ReusePort    bool   `toml:"reuse_port"`      // включить SO_REUSEPORT для multi-listener bind
		UDPRcv       int    `toml:"udp_rbuf"`        // запрошенный SO_RCVBUF; 0 → 32MiB
		UDPSnd       int    `toml:"udp_wbuf"`        // запрошенный SO_SNDBUF; 0 → 32MiB
		ZeroCopy     bool   `toml:"zerocopy"`        // deprecated: игнорируется, сохранено для совместимости конфига
		ZCMinBytes   int    `toml:"zc_min_bytes"`    // deprecated: сохранено для совместимости конфига
		UDPGSOMSS    int    `toml:"udpgso_mss"`      // deprecated: игнорируется, сохранено для совместимости конфига
		AggregateInn bool   `toml:"aggregate_inner"` // deprecated: игнорируется, сохранено для совместимости конфига
	} `toml:"transport"`
	Map struct {
		Path string `toml:"path"` // путь к мэппингу: серый_IP → "белый ip:port"; "" → "conf/peers.toml"
	} `toml:"map"`
	Batch struct {
		Hold   time.Duration `toml:"hold"`   // макс удержание TX-батча и шаг опроса; 0 → 5ms
		Warmup time.Duration `toml:"warmup"` // длительность прогрева; 0 → 2s
	} `toml:"batch"`
	Log struct {
		Level string `toml:"level"` // debug|info|warn|error; "" → info
	} `toml:"log"`
	Debug struct {
		PprofListen string `toml:"pprof_listen"` // HTTP pprof bind; "" → disabled
	} `toml:"debug"`
}

// peersTOML — формат TOML файла мэппинга пиров.
type peersTOML struct {
	Peers map[string]string `toml:"peers"`
}

// tunDevice — одна очередь TUN (один fd).
type tunDevice struct {
	fd int // файловый дескриптор /dev/net/tun
}

// tunBundle — один TUN интерфейс с одной или несколькими очередями.
type tunBundle struct {
	name      string
	queues    []*tunDevice
	closeOnce sync.Once
}

// rxPacket — буфер inner-пакета для передачи от UDP reader к TUN writer.
type rxPacket struct {
	buf []byte
}

// txPacket — inner-пакет и его уже разрешённый UDP endpoint для TX flush.
type txPacket struct {
	buf      []byte
	endpoint resolvedEndpoint
}

// rxIngressStats — счётчики давления на RX очередь и записи в TUN.
type rxIngressStats struct {
	enqueued       atomic.Uint64
	written        atomic.Uint64
	queueWaits     atomic.Uint64
	queueHighWater atomic.Uint64
	tunWriteWaits  atomic.Uint64
}

// rxIngress — общий bounded queue между UDP readers и одним TUN writer.
type rxIngress struct {
	packets chan rxPacket
	pool    *sync.Pool
	tun     *tunDevice
	effMTU  int
	stats   rxIngressStats
}

// resolvedEndpoint — нормализованный IPv4 endpoint и готовые адресные формы для отправки.
type resolvedEndpoint struct {
	key     string
	gsoKey  uint64
	udpAddr *net.UDPAddr
	sock4   *unix.SockaddrInet4
}

// peerMap — неизменяемая карта серый_IP→endpoint под atomic.Value.
type peerMap struct {
	v atomic.Value // map[uint32]resolvedEndpoint
}

// udpState — UDP-сокет и служебное состояние для логов/прогрева.
type udpState struct {
	conn   *net.UDPConn
	pc     *ipv4.PacketConn
	fd     int
	zerocp bool
	zcMin  int
	txGSO  atomic.Bool

	rcvSz int // фактический SO_RCVBUF
	sndSz int // фактический SO_SNDBUF

	shared    *udpShared
	closeOnce sync.Once
}

// udpShared — общее состояние нескольких reuseport listeners.
type udpShared struct {
	logMu   sync.Mutex
	lastLog map[string]time.Time

	logCool     time.Duration
	warmupUntil atomic.Value // time.Time
}

// udpBundle — набор UDP listeners на одном адресе/порту.
type udpBundle struct {
	listeners []*udpState
	primary   *udpState
	closeOnce sync.Once
}

const tunWriteRetryWait = 250 * time.Microsecond

//
// ============================== Утилиты ===============================
//

// parseLevel — строка уровня → slog.Level.
// Вход: строка уровня. Выход: slog.Level.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// loadConfig — загрузка TOML и дефолты.
// Вход: путь к файлу. Выход: Config или ошибка.
func loadConfig(path string) (Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "tun0"
	}
	if cfg.Tun.Queues == 0 {
		cfg.Tun.Queues = 1
	}
	if cfg.Tun.Queues < 1 || cfg.Tun.Queues > 64 {
		return cfg, errors.New("tun.queues вне диапазона 1..64")
	}
	if cfg.Tun.LinkMTU == 0 {
		cfg.Tun.LinkMTU = 9000
	}
	if cfg.Tun.LinkMTU < 576 || cfg.Tun.LinkMTU > 65535 {
		return cfg, errors.New("link_mtu вне диапазона 576..65535")
	}
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 9000
	}
	if cfg.Tun.MTU < 576 || cfg.Tun.MTU > 65535 {
		return cfg, errors.New("mtu вне диапазона 576..65535")
	}
	if cfg.Transport.Listen == "" {
		cfg.Transport.Listen = "0.0.0.0:5555"
	}
	if cfg.Transport.Listeners == 0 {
		cfg.Transport.Listeners = 1
	}
	if cfg.Transport.Listeners < 1 || cfg.Transport.Listeners > 64 {
		return cfg, errors.New("transport.listeners вне диапазона 1..64")
	}
	if cfg.Transport.Listeners > 1 && !cfg.Transport.ReusePort {
		return cfg, errors.New("transport.listeners > 1 требует reuse_port=true")
	}
	if cfg.Transport.UDPRcv == 0 {
		cfg.Transport.UDPRcv = 32 << 20
	}
	if cfg.Transport.UDPSnd == 0 {
		cfg.Transport.UDPSnd = 32 << 20
	}
	if cfg.Transport.ZCMinBytes <= 0 {
		cfg.Transport.ZCMinBytes = 8192
	}
	if cfg.Map.Path == "" {
		cfg.Map.Path = "conf/peers.toml"
	}
	if cfg.Batch.Hold == 0 {
		cfg.Batch.Hold = 5 * time.Millisecond
	}
	if cfg.Batch.Warmup == 0 {
		cfg.Batch.Warmup = 2 * time.Second
	}
	return cfg, nil
}

// startPprofServer — запустить HTTP pprof сервер до отмены контекста.
// Вход: ctx, listen. Выход: ошибка бинда или nil.
func startPprofServer(ctx context.Context, listen string) error {
	if strings.TrimSpace(listen) == "" {
		return nil
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("pprof serve", "listen", listen, "err", err)
		}
	}()
	slog.Info("pprof started", "listen", listen)
	return nil
}

// clamp — ограничить x в [lo,hi].
// Вход: x, lo, hi. Выход: значение в пределах.
func clamp(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// rip4 — IPv4 → BE u32 ключ.
// Вход: net.IP. Выход: uint32 (0 если не IPv4).
func rip4(ip net.IP) uint32 {
	b := ip.To4()
	if b == nil {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// isWouldBlockErr — true для EAGAIN/EWOULDBLOCK.
// Вход: err. Выход: bool.
func isWouldBlockErr(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}

// isTempRecvErr — временные ошибки RX.
// Вход: err. Выход: true если ошибку можно переждать и продолжить.
func isTempRecvErr(err error) bool {
	if err == nil {
		return false
	}
	if isWouldBlockErr(err) || errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return true
		}
		return isTempRecvErr(ne.Err)
	}
	var se *os.SyscallError
	if errors.As(err, &se) {
		return isTempRecvErr(se.Err)
	}
	return false
}

// waitFD — дождаться события на fd c точностью до наносекунд.
// Вход: fd, events, timeout; timeout < 0 означает ждать без дедлайна. Выход: ошибка ОС или nil.
func waitFD(fd int32, events int16, timeout time.Duration) error {
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

// resolveIPv4Endpoint — нормализовать и заранее подготовить IPv4 UDP endpoint.
// Вход: raw endpoint "host:port". Выход: resolvedEndpoint или ошибка.
func resolveIPv4Endpoint(raw string) (resolvedEndpoint, error) {
	addr, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(raw))
	if err != nil {
		return resolvedEndpoint{}, err
	}
	if addr == nil || addr.IP == nil {
		return resolvedEndpoint{}, errors.New("empty resolved endpoint")
	}
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return resolvedEndpoint{}, errors.New("IPv4 endpoint required")
	}
	udpAddr := &net.UDPAddr{IP: append(net.IP(nil), ip4...), Port: addr.Port}
	sock4 := &unix.SockaddrInet4{Port: addr.Port}
	copy(sock4.Addr[:], ip4)
	return resolvedEndpoint{
		key:     net.JoinHostPort(udpAddr.IP.String(), strconv.Itoa(udpAddr.Port)),
		gsoKey:  uint64(rip4(ip4))<<16 | uint64(uint16(addr.Port)),
		udpAddr: udpAddr,
		sock4:   sock4,
	}, nil
}

// ioctl константы для TUN (без vnet_hdr/mergeable).
const (
	iffTUN        = 0x0001
	iffNO_PI      = 0x1000
	iffMULTIQueue = 0x0100
	IFNAMSIZ      = 16
	TUNSETIFF     = 0x400454ca
)

// ifreq — аргумент ioctl(TUNSETIFF).
type ifreq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

// openTUNQueue — открыть /dev/net/tun и привязать одну очередь интерфейса.
// Вход: name, flags. Выход: *tunDevice или ошибка.
func openTUNQueue(name string, flags uint16) (*tunDevice, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("open /dev/net/tun: " + err.Error())
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = flags
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, errors.New("ioctl TUNSETIFF: " + errno.Error())
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &tunDevice{fd: fd}, nil
}

// openTUN — открыть одну или несколько очередей TUN под одним именем интерфейса.
// Вход: name, queueCount. Выход: *tunBundle или ошибка.
func openTUN(name string, queueCount int) (*tunBundle, error) {
	flags := uint16(iffTUN | iffNO_PI)
	if queueCount > 1 {
		flags |= iffMULTIQueue
	}
	bundle := &tunBundle{name: name, queues: make([]*tunDevice, 0, queueCount)}
	for i := 0; i < queueCount; i++ {
		tun, err := openTUNQueue(name, flags)
		if err != nil {
			_ = bundle.Close()
			return nil, err
		}
		bundle.queues = append(bundle.queues, tun)
	}
	return bundle, nil
}

// ReadNB — неблокирующее чтение L3-пакета из очереди TUN.
// Вход: p — буфер (вмещает linkMTU). Выход: длина L3; 0 при EAGAIN; ошибка при сбое.
func (t *tunDevice) ReadNB(p []byte) (int, error) {
	n, err := syscall.Read(t.fd, p)
	if isWouldBlockErr(err) {
		return 0, nil
	}
	return n, err
}

// WriteL3 — запись L3-пакета в очередь TUN.
// Вход: pkt — L3 пакет. Выход: число записанных байт или ошибка.
func (t *tunDevice) WriteL3(pkt []byte) (int, error) {
	return syscall.Write(t.fd, pkt)
}

// WriteL3Context — записать L3-пакет в TUN, дождавшись writable при EAGAIN.
// Вход: ctx, pkt, waitCounter. Выход: ошибка записи или nil.
func (t *tunDevice) WriteL3Context(ctx context.Context, pkt []byte, waitCounter *atomic.Uint64) error {
	for {
		n, err := t.WriteL3(pkt)
		if err == nil {
			if n != len(pkt) {
				return fmt.Errorf("short tun write: %d of %d", n, len(pkt))
			}
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if isWouldBlockErr(err) {
			if waitCounter != nil {
				waitCounter.Add(1)
			}
			if err := waitFD(int32(t.fd), unix.POLLOUT, tunWriteRetryWait); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			continue
		}
		return err
	}
}

// Close — закрыть все очереди TUN.
// Вход: нет. Выход: первая ошибка ОС (если была).
func (t *tunBundle) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		for _, q := range t.queues {
			if err := syscall.Close(q.fd); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}

// configureTUN — поднять интерфейс, адрес/MTU, при необходимости маршрут.
// Вход: name, cidr, linkMTU, addRoute. Выход: фактический MTU линка или ошибка.
func configureTUN(name, cidr string, linkMTU int, addRoute bool) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, errors.New("link not found: " + err.Error())
	}
	if linkMTU > 0 {
		if err := netlink.LinkSetMTU(link, linkMTU); err != nil {
			return 0, errors.New("set mtu: " + err.Error())
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, errors.New("link up: " + err.Error())
	}
	if cidr != "" {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return 0, errors.New("addr parse: " + err.Error())
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return 0, errors.New("IPv4 only")
		}
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip4, Mask: ipnet.Mask}}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return 0, errors.New("addr set: " + err.Error())
		}
		if addRoute {
			dst := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}
			rt := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
			if err := netlink.RouteReplace(rt); err != nil {
				return 0, errors.New("route add: " + err.Error())
			}
		}
	}
	link, _ = netlink.LinkByName(name)
	return link.Attrs().MTU, nil
}

// addGrayRoutes — добавить маршруты доп. подсетей в TUN.
// В вход: tunName, список CIDR. Выход: ошибка при парсинге/системных вызовах.
func addGrayRoutes(tunName string, cidrs []string) error {
	if len(cidrs) == 0 {
		return nil
	}
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return errors.New("link not found: " + err.Error())
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return errors.New("gray-route parse: " + err.Error())
		}
		if ipnet.IP.To4() == nil {
			return errors.New("gray-route: только IPv4")
		}
		rt := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet}
		if err := netlink.RouteReplace(rt); err != nil {
			return errors.New("gray-route add: " + err.Error())
		}
	}
	return nil
}

//
// ======================== Мэппинг адресов ========================
//

// newPeerMap — создать пустую атомарную карту.
// Вход: нет. Выход: *peerMap.
func newPeerMap() *peerMap {
	pm := &peerMap{}
	pm.v.Store(make(map[uint32]resolvedEndpoint))
	return pm
}

// loadFromTOML — загрузить мэппинг и атомарно заменить карту.
// Вход: путь к TOML. Выход: ошибка при парсинге/валидации.
func (pm *peerMap) loadFromTOML(path string) error {
	var pf peersTOML
	if _, err := toml.DecodeFile(path, &pf); err != nil {
		return err
	}
	if len(pf.Peers) == 0 {
		return errors.New("empty peers in mapping TOML")
	}
	tmp := make(map[uint32]resolvedEndpoint, len(pf.Peers))
	for gray, white := range pf.Peers {
		ip := net.ParseIP(strings.TrimSpace(gray))
		if ip == nil || ip.To4() == nil {
			return errors.New("map: IPv4 required: " + gray)
		}
		endpoint, err := resolveIPv4Endpoint(white)
		if err != nil {
			return errors.New("map: endpoint invalid for " + gray + ": " + err.Error())
		}
		tmp[rip4(ip)] = endpoint
	}
	pm.v.Store(tmp)
	return nil
}

// lookup — быстрый поиск endpoint по dst IPv4 без блокировок.
// Вход: dstIPv4 — 4 байта адреса. Выход: endpoint и ok.
func (pm *peerMap) lookup(dstIPv4 []byte) (resolvedEndpoint, bool) {
	if len(dstIPv4) != 4 {
		return resolvedEndpoint{}, false
	}
	key := uint32(dstIPv4[0])<<24 | uint32(dstIPv4[1])<<16 | uint32(dstIPv4[2])<<8 | uint32(dstIPv4[3])
	m := pm.v.Load().(map[uint32]resolvedEndpoint)
	endpoint, ok := m[key]
	return endpoint, ok
}

// endpoints — уникальные endpoints для прогрева.
// Вход: нет. Выход: список уникальных "ip:port".
func (pm *peerMap) endpoints() []resolvedEndpoint {
	m := pm.v.Load().(map[uint32]resolvedEndpoint)
	seen := make(map[string]struct{}, len(m))
	out := make([]resolvedEndpoint, 0, len(m))
	for _, endpoint := range m {
		if _, ok := seen[endpoint.key]; ok {
			continue
		}
		seen[endpoint.key] = struct{}{}
		out = append(out, endpoint)
	}
	return out
}

//
// ============================= IPv4 utils ============================
//

// ipv4Dst — извлечь dst IPv4 из заголовка IPv4-пакета.
// Вход: pkt. Выход: срез pkt[16:20], ok.
func ipv4Dst(pkt []byte) ([]byte, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, false
	}
	return pkt[16:20], true
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

//
// =============================== UDP ================================
//

// newUDPState — обернуть UDP сокет, включить опции и собрать runtime state.
// Вход: conn, rcv, snd, zerocopy, zcMin, shared. Выход: *udpState или ошибка.
func newUDPState(conn *net.UDPConn, rcv, snd int, zerocopy bool, zcMin int, shared *udpShared) (*udpState, error) {
	// запросить размеры буферов от конфигурации
	_ = conn.SetReadBuffer(rcv)
	_ = conn.SetWriteBuffer(snd)

	pc := ipv4.NewPacketConn(conn)

	// сырой fd
	var fd int
	if sc, err := conn.SyscallConn(); err == nil {
		_ = sc.Control(func(f uintptr) { fd = int(f) })
	}

	u := &udpState{
		conn:   conn,
		pc:     pc,
		fd:     fd,
		zerocp: false,
		zcMin:  zcMin,
		rcvSz:  rcv,
		sndSz:  snd,
		shared: shared,
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
			u.rcvSz = sz
		}
		if sz, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF); err == nil {
			u.sndSz = sz
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

// newUDPBundle — создать один или несколько reuseport-bound UDP listeners.
// Вход: listen, listenerCount, rcv, snd, reusePort, zerocopy, zcMin. Выход: *udpBundle или ошибка.
func newUDPBundle(listen string, listenerCount, rcv, snd int, reusePort, zerocopy bool, zcMin int) (*udpBundle, error) {
	shared := &udpShared{
		lastLog: make(map[string]time.Time),
		logCool: 5 * time.Second,
	}
	shared.warmupUntil.Store(time.Time{})
	bundle := &udpBundle{listeners: make([]*udpState, 0, listenerCount)}
	for i := 0; i < listenerCount; i++ {
		conn, err := listenUDP(listen, reusePort)
		if err != nil {
			bundle.close()
			return nil, err
		}
		u, err := newUDPState(conn, rcv, snd, zerocopy, zcMin, shared)
		if err != nil {
			_ = conn.Close()
			bundle.close()
			return nil, err
		}
		bundle.listeners = append(bundle.listeners, u)
	}
	if len(bundle.listeners) == 0 {
		return nil, errors.New("no UDP listeners created")
	}
	bundle.primary = bundle.listeners[0]
	return bundle, nil
}

// close — закрыть UDP listener.
// Вход: нет. Выход: нет.
func (u *udpState) close() {
	u.closeOnce.Do(func() {
		_ = u.pc.Close()
		_ = u.conn.Close()
	})
}

// txGSOEnabled — текущее состояние runtime-поддержки UDP_SEGMENT на сокете.
// Вход: нет. Выход: true если TX может пытаться коалесцировать sendmsg.
func (u *udpState) txGSOEnabled() bool {
	return u.txGSO.Load()
}

// disableTxGSO — выключить GSO после ошибки пути/ядра и залогировать это один раз.
// Вход: err. Выход: нет.
func (u *udpState) disableTxGSO(err error) {
	if u.txGSO.CompareAndSwap(true, false) {
		slog.Warn("udp gso off", "err", err)
	}
}

// close — закрыть весь UDP bundle.
// Вход: нет. Выход: нет.
func (b *udpBundle) close() {
	b.closeOnce.Do(func() {
		for _, u := range b.listeners {
			u.close()
		}
	})
}

// setWarmupUntil — установить дедлайн прогрева.
// Вход: t. Выход: нет.
func (u *udpState) setWarmupUntil(t time.Time) {
	u.shared.warmupUntil.Store(t)
}

// inWarmup — true, пока не истёк дедлайн прогрева.
// Вход: now. Выход: bool.
func (u *udpState) inWarmup(now time.Time) bool {
	return now.Before(u.shared.warmupUntil.Load().(time.Time))
}

// phase — текущая фаза: "warmup" или "tx".
// Вход: нет. Выход: строка фазы.
func (u *udpState) phase() string {
	if u.inWarmup(time.Now()) {
		return "warmup"
	}
	return "tx"
}

// notePeerUnavailable — троттлинг сообщений об ошибках доставки.
// Вход: ep, phase, reason, err. Выход: нет.
func (u *udpState) notePeerUnavailable(ep, phase, reason string, err error) {
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

// newRXIngress — создать общую RX очередь и TUN writer state.
// Вход: tun, effMTU, queueDepth. Выход: *rxIngress.
func newRXIngress(tun *tunDevice, effMTU, queueDepth int) *rxIngress {
	return &rxIngress{
		packets: make(chan rxPacket, queueDepth),
		pool: &sync.Pool{
			New: func() any { return make([]byte, effMTU) },
		},
		tun:    tun,
		effMTU: effMTU,
	}
}

// noteQueueDepth — обновить high-water mark RX очереди.
// Вход: depth. Выход: нет.
func (r *rxIngress) noteQueueDepth(depth int) {
	for {
		old := r.stats.queueHighWater.Load()
		if uint64(depth) <= old || r.stats.queueHighWater.CompareAndSwap(old, uint64(depth)) {
			return
		}
	}
}

// enqueuePacket — скопировать пакет в RX очередь для TUN writer.
// Вход: ctx, pkt. Выход: ошибка или nil.
func (r *rxIngress) enqueuePacket(ctx context.Context, pkt []byte) error {
	buf := r.pool.Get().([]byte)
	copy(buf[:len(pkt)], pkt)
	packet := rxPacket{buf: buf[:len(pkt)]}

	select {
	case r.packets <- packet:
		r.stats.enqueued.Add(1)
		r.noteQueueDepth(len(r.packets))
		return nil
	default:
		r.stats.queueWaits.Add(1)
	}

	select {
	case r.packets <- packet:
		r.stats.enqueued.Add(1)
		r.noteQueueDepth(len(r.packets))
		return nil
	case <-ctx.Done():
		r.pool.Put(packet.buf[:r.effMTU])
		return nil
	}
}

// drainPackets — вернуть буферы из очереди в pool.
// Вход: нет. Выход: нет.
func (r *rxIngress) drainPackets() {
	for {
		select {
		case pkt := <-r.packets:
			r.pool.Put(pkt.buf[:r.effMTU])
		default:
			return
		}
	}
}

// writeLoop — отдельный writer RX очереди в TUN.
// Вход: ctx. Выход: ошибка или nil.
func (r *rxIngress) writeLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			r.drainPackets()
			return nil
		case pkt := <-r.packets:
			if err := r.tun.WriteL3Context(ctx, pkt.buf, &r.stats.tunWriteWaits); err != nil {
				r.pool.Put(pkt.buf[:r.effMTU])
				if ctx.Err() != nil {
					r.drainPackets()
					return nil
				}
				r.drainPackets()
				return fmt.Errorf("tun write: %w", err)
			}
			r.stats.written.Add(1)
			r.pool.Put(pkt.buf[:r.effMTU])
		}
	}
}

// logStats — записать итоговые счётчики RX очереди.
// Вход: нет. Выход: нет.
func (r *rxIngress) logStats() {
	slog.Info("rx ingress stats",
		"enqueued", r.stats.enqueued.Load(),
		"written", r.stats.written.Load(),
		"queue_waits", r.stats.queueWaits.Load(),
		"queue_high_water", r.stats.queueHighWater.Load(),
		"queue_depth", len(r.packets),
		"queue_capacity", cap(r.packets),
		"tun_write_waits", r.stats.tunWriteWaits.Load(),
	)
}

// isTempSendErr — временные ошибки TX.
// Вход: err. Выход: true если временная.
func isTempSendErr(err error) bool {
	if err == nil {
		return false
	}
	if isWouldBlockErr(err) || errors.Is(err, syscall.ENOBUFS) {
		return true
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return true
		}
		return isTempSendErr(ne.Err)
	}
	var se *os.SyscallError
	if errors.As(err, &se) {
		return isTempSendErr(se.Err)
	}
	return false
}

// gsoBatchEnd — найти максимальную допустимую GSO-группу от start.
// Вход: packets, start. Выход: индекс конца [start:end) для одного sendmsg.
func gsoBatchEnd(packets []txPacket, start int) int {
	if start >= len(packets) {
		return start
	}
	const maxUDPSegments = 64
	segSize := len(packets[start].buf)
	if segSize <= 0 {
		return start + 1
	}
	endpointKey := packets[start].endpoint.gsoKey
	end := start + 1
	for end < len(packets) && end-start < maxUDPSegments {
		if packets[end].endpoint.gsoKey != endpointKey {
			break
		}
		segLen := len(packets[end].buf)
		if segLen <= 0 || segLen > segSize {
			break
		}
		end++
		if segLen < segSize {
			break
		}
	}
	if end-start < 2 {
		return start + 1
	}
	return end
}

// writeBatchMessages — отправить обычный UDP batch через WriteBatch.
// Вход: ctx, udp, msgs. Выход: ошибка отправки или nil.
func writeBatchMessages(ctx context.Context, udp *udpState, msgs []ipv4.Message) error {
	for off := 0; off < len(msgs); {
		n, err := udp.pc.WriteBatch(msgs[off:], 0)
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

// sendGSOBatch — отправить несколько inner-пакетов одним sendmsg с UDP_SEGMENT.
// Вход: ctx, udp, packets, buffers, oob. Выход: ошибка отправки или nil.
func sendGSOBatch(ctx context.Context, udp *udpState, packets []txPacket, buffers [][]byte, oob []byte) error {
	if len(packets) < 2 {
		return errors.New("udp gso batch requires at least 2 packets")
	}
	if len(buffers) < len(packets) {
		return errors.New("udp gso batch buffers too small")
	}
	segSize := len(packets[0].buf)
	totalBytes := 0
	for i := range packets {
		buffers[i] = packets[i].buf
		totalBytes += len(packets[i].buf)
	}
	n, err := unix.SendmsgBuffers(udp.fd, buffers[:len(packets)], udpSegmentControlMessage(oob, segSize), packets[0].endpoint.sock4, 0)
	if err != nil {
		if shouldDisableUDPGSO(err) {
			udp.disableTxGSO(err)
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

// startErrMonitor — дренаж error-queue для логов ICMP.
// Вход: ctx, tick. Выход: нет.
func (u *udpState) startErrMonitor(ctx context.Context, tick time.Duration) {
	if u.fd <= 0 {
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
		pfd := []unix.PollFd{{Fd: int32(u.fd), Events: unix.POLLERR}}
		timeoutMS := int(tick / time.Millisecond)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, _ = unix.Poll(pfd, timeoutMS)
			for {
				n, oobn, _, _, err := unix.Recvmsg(u.fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
				if isWouldBlockErr(err) {
					break
				}
				if err != nil {
					return
				}
				_ = oobn
				if ep, ok := parseUDPEndpointFromICMPPayload(buf[:n]); ok {
					u.notePeerUnavailable(ep, u.phase(), "icmp_unreachable", nil)
				}
			}
		}
	}()
}

// parseUDPEndpointFromICMPPayload — извлечь "dstIP:dstPort" из вложенного IPv4+UDP.
// Вход: buf. Выход: endpoint, ok.
func parseUDPEndpointFromICMPPayload(buf []byte) (string, bool) {
	// Проверяем, что это ICMP Destination Unreachable (тип 3)
	if len(buf) < 8 || buf[0] != 3 {
		return "", false
	}
	// Пропускаем ICMP заголовок (8 байт) и начинаем с вложенного IP пакета
	ipPayload := buf[8:]
	if len(ipPayload) < 20 || ipPayload[0]>>4 != 4 {
		return "", false
	}
	ihl := int(ipPayload[0]&0x0F) * 4
	if ihl < 20 || len(ipPayload) < ihl+8 {
		return "", false
	}
	dstIP := net.IPv4(ipPayload[16], ipPayload[17], ipPayload[18], ipPayload[19]).String()
	udpOff := ihl
	if len(ipPayload) < udpOff+4 {
		return "", false
	}
	dstPort := int(binary.BigEndian.Uint16(ipPayload[udpOff+2 : udpOff+4]))
	return net.JoinHostPort(dstIP, strconv.Itoa(dstPort)), true
}

// =============================== main ================================
//

var cfgPath = flag.String("config", "overlay.toml", "путь к конфигу TOML")

// main — инициализация, прогрев, запуск конвейеров.
// Вход: флаги командной строки. Выход: код завершения процесса (через os.Exit).
func main() {
	flag.Parse()
	runtime.GOMAXPROCS(0)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("config load", "err", err)
		os.Exit(1)
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.Log.Level)})
	slog.SetDefault(slog.New(h))
	if cfg.Transport.AggregateInn || cfg.Transport.UDPGSOMSS > 0 {
		slog.Warn("deprecated transport options ignored",
			"aggregate_inner", cfg.Transport.AggregateInn,
			"udpgso_mss", cfg.Transport.UDPGSOMSS,
		)
	}
	if cfg.Transport.ZeroCopy {
		slog.Warn("transport.zerocopy ignored", "reason", "runtime path disabled until completion tracking is implemented")
	}

	pm := newPeerMap()
	if err := pm.loadFromTOML(cfg.Map.Path); err != nil {
		slog.Error("map load", "err", err)
		os.Exit(1)
	}

	// Открыть TUN (чистый L3).
	tun, err := openTUN(cfg.Tun.Name, cfg.Tun.Queues)
	if err != nil {
		slog.Error("tun open", "err", err)
		os.Exit(1)
	}
	defer tun.Close()

	// Контекст завершения.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := startPprofServer(ctx, cfg.Debug.PprofListen); err != nil {
		slog.Error("pprof start", "listen", cfg.Debug.PprofListen, "err", err)
		os.Exit(1)
	}

	// Настройка линка/адреса/маршрутов.
	reqLinkMTU := cfg.Tun.LinkMTU
	linkMTU, err := configureTUN(cfg.Tun.Name, cfg.Tun.Addr, reqLinkMTU, cfg.Tun.AddRoute)
	if err != nil {
		slog.Error("tun configure", "err", err)
		os.Exit(1)
	}
	if err := addGrayRoutes(cfg.Tun.Name, cfg.Tun.GrayRoutes); err != nil {
		slog.Error("routes add", "err", err)
		os.Exit(1)
	}

	// Эффективный MTU inner = min(cfg.MTU, link_mtu-28), clamp [576..].
	const outerOverhead = 28
	maxInner := linkMTU - outerOverhead
	if maxInner < 576 {
		maxInner = 576
	}
	effMTU := cfg.Tun.MTU
	if effMTU > maxInner {
		slog.Debug("eff_mtu clamped by link_mtu-28",
			"requested_mtu", cfg.Tun.MTU, "link_mtu", linkMTU, "outer_overhead", outerOverhead, "new_eff_mtu", maxInner)
		effMTU = maxInner
	}
	if effMTU < 576 {
		effMTU = 576
	}
	// Держим фактический MTU TUN согласованным с безопасным inner MTU,
	// иначе локальный стек начнёт генерировать inner-пакеты больше effMTU.
	if linkMTU > effMTU {
		if link, err := netlink.LinkByName(cfg.Tun.Name); err == nil {
			if err := netlink.LinkSetMTU(link, effMTU); err != nil {
				slog.Warn("lower link_mtu failed", "want", effMTU, "err", err)
			} else {
				slog.Debug("lower link_mtu to eff_mtu", "old", linkMTU, "new", effMTU)
				linkMTU = effMTU
			}
		}
	}
	udp, err := newUDPBundle(cfg.Transport.Listen, cfg.Transport.Listeners,
		cfg.Transport.UDPRcv, cfg.Transport.UDPSnd, cfg.Transport.ReusePort,
		false, cfg.Transport.ZCMinBytes)
	if err != nil {
		slog.Error("udp listen", "err", err)
		os.Exit(1)
	}
	defer udp.close()
	udp.primary.setWarmupUntil(time.Now().Add(cfg.Batch.Warmup))

	// Период опроса error-queue = min(hold, 20ms).
	errqTick := cfg.Batch.Hold
	if errqTick <= 0 || errqTick > 20*time.Millisecond {
		errqTick = 20 * time.Millisecond
	}
	udp.primary.startErrMonitor(ctx, errqTick)

	// Адаптивные батчи от фактических буферов сокета, но с жёстким upper bound,
	// чтобы не устраивать локальные microbursts.
	const maxRXBatchBytes = 512 << 10
	const maxRXBurstPackets = 64
	const maxTXBatchBytes = 64 << 10
	const maxTXBurstPackets = 4
	targetBatchBytesRX := clamp(udp.primary.rcvSz/4, effMTU, maxRXBatchBytes)
	targetBatchBytesTX := clamp(udp.primary.sndSz/4, effMTU, maxTXBatchBytes)
	perListenerBatchBytesRX := clamp(targetBatchBytesRX/len(udp.listeners), effMTU, 2<<20)
	pktLimitRX := clamp(perListenerBatchBytesRX/effMTU, 1, maxRXBurstPackets)
	pktLimitTX := clamp(targetBatchBytesTX/effMTU, 1, maxTXBurstPackets)
	perWorkerPktLimitTX := clamp(pktLimitTX/len(tun.queues), 1, 2048)
	rxQueueDepth := clamp(pktLimitRX*8, 256, 4096)
	txMaxHold := cfg.Batch.Hold
	if txMaxHold <= 0 || txMaxHold > 25*time.Microsecond {
		txMaxHold = 25 * time.Microsecond
	}

	slog.Debug("Starting...",
		"listen", cfg.Transport.Listen,
		"udp_listeners", len(udp.listeners), "reuse_port", cfg.Transport.ReusePort,
		"udp_rbuf_req", cfg.Transport.UDPRcv, "udp_wbuf_req", cfg.Transport.UDPSnd,
		"udp_rbuf_act", udp.primary.rcvSz, "udp_wbuf_act", udp.primary.sndSz,
		"batch_bytes_rx", targetBatchBytesRX, "batch_bytes_tx", targetBatchBytesTX,
		"batch_bytes_rx_listener", perListenerBatchBytesRX,
		"rx_queue_depth", rxQueueDepth,
		"pkt_limit_rx_listener", pktLimitRX, "pkt_limit_tx_total", pktLimitTX,
		"pkt_limit_tx_worker", perWorkerPktLimitTX,
		"cfg_mtu", cfg.Tun.MTU, "link_mtu", linkMTU, "eff_mtu", effMTU,
		"hold", cfg.Batch.Hold, "tx_hold", txMaxHold, "warmup", cfg.Batch.Warmup,
		"udp_gso", udp.primary.txGSOEnabled(),
		"zerocopy", udp.primary.zerocp,
		"tun", cfg.Tun.Name, "tun_queues", len(tun.queues),
	)

	slog.Info("Service started", "tun", cfg.Tun.Name, "tun_queues", len(tun.queues))

	// Прогрев пиров.
	prewarmEndpoints(udp.primary, pm)

	var wg sync.WaitGroup
	errCh := make(chan error, len(tun.queues)+len(udp.listeners)+16)
	rxIngress := newRXIngress(tun.queues[0], effMTU, rxQueueDepth)

	reportAsyncErr := func(name string, err error) {
		select {
		case errCh <- fmt.Errorf("%s: %w", name, err):
		default:
		}
		stop()
	}

	runWorker := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				reportAsyncErr(name, err)
			}
		}()
	}

	runWorker("rx-write", func() error {
		return rxIngress.writeLoop(ctx)
	})
	for idx, rxUDP := range udp.listeners {
		idx := idx
		rxUDP := rxUDP
		workerName := fmt.Sprintf("rx[%d]", idx)
		runWorker(workerName, func() error {
			return rxReadLoop(ctx, rxUDP, rxIngress, effMTU, pktLimitRX)
		})
	}
	for idx, queue := range tun.queues {
		idx := idx
		queue := queue
		workerName := fmt.Sprintf("tx[%d]", idx)
		runWorker(workerName, func() error {
			return txLoop(ctx, udp.primary, pm, queue, linkMTU, effMTU, perWorkerPktLimitTX, txMaxHold)
		})
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	if runErr == nil {
		select {
		case runErr = <-errCh:
		default:
		}
	}

	udp.close()
	_ = tun.Close()
	wg.Wait()
	rxIngress.logStats()
	if runErr == nil {
		select {
		case runErr = <-errCh:
		default:
		}
	}
	if runErr != nil {
		slog.Error("worker failed", "err", runErr)
		os.Exit(1)
	}
}

//
// ============================ Конвейеры ===============================
//

// rxReadLoop — приём UDP батчами и быстрая постановка inner-пакетов в RX очередь.
// Вход: ctx, udp, ingress, effMTU, pktLimit. Выход: ошибка worker или nil.
func rxReadLoop(ctx context.Context, udp *udpState, ingress *rxIngress, effMTU, pktLimit int) error {
	N := clamp(pktLimit*4, 64, 512)
	msgs := make([]ipv4.Message, N)
	bufs := make([][]byte, N)
	for i := 0; i < N; i++ {
		bufs[i] = make([]byte, effMTU)
		msgs[i].Buffers = [][]byte{bufs[i]}
	}
	for {
		n, err := udp.pc.ReadBatch(msgs, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isTempRecvErr(err) {
				time.Sleep(200 * time.Microsecond)
				continue
			}
			return fmt.Errorf("udp read batch: %w", err)
		}
		if n <= 0 {
			continue
		}
		for i := 0; i < n; i++ {
			ln := msgs[i].N
			if ln <= 0 || ln > effMTU {
				continue
			}
			if _, ok := ipv4Dst(bufs[i][:ln]); !ok {
				continue
			}
			if err := ingress.enqueuePacket(ctx, bufs[i][:ln]); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("rx enqueue: %w", err)
			}
		}
	}
}

// txLoop — чтение из одной очереди TUN и отправка UDP.
// Вход: ctx, udp, pm, tun, linkMTU, effMTU, pktLimit, maxHold. Выход: ошибка worker или nil.
func txLoop(ctx context.Context, udp *udpState, pm *peerMap, tun *tunDevice, linkMTU, effMTU, pktLimit int, maxHold time.Duration) error {
	N := clamp(pktLimit*2, 16, 128)

	// Буферы чтения из TUN.
	readBufs := make([][]byte, N)
	for i := 0; i < N; i++ {
		readBufs[i] = make([]byte, linkMTU)
	}

	// Копирующий путь: заранее 1 слот в Buffers.
	msgs := make([]ipv4.Message, N)
	for i := 0; i < N; i++ {
		msgs[i].Buffers = make([][]byte, 1)
	}
	packets := make([]txPacket, N)
	gsoBuffers := make([][]byte, N)
	gsoOOB := make([]byte, unix.CmsgSpace(2))

	k := 0
	batchStart := time.Now()

	flushPackets := func() error {
		if k == 0 {
			batchStart = time.Now()
			return nil
		}
		if !udp.txGSOEnabled() {
			if err := writeBatchMessages(ctx, udp, msgs[:k]); err != nil {
				return err
			}
			k = 0
			batchStart = time.Now()
			return nil
		}

		copyStart := 0
		for off := 0; off < k; {
			gsoEnd := gsoBatchEnd(packets[:k], off)
			if gsoEnd-off < 2 {
				off++
				continue
			}
			if copyStart < off {
				if err := writeBatchMessages(ctx, udp, msgs[copyStart:off]); err != nil {
					return err
				}
			}
			if err := sendGSOBatch(ctx, udp, packets[off:gsoEnd], gsoBuffers, gsoOOB); err != nil {
				if !udp.txGSOEnabled() || isTempSendErr(err) {
					if err := writeBatchMessages(ctx, udp, msgs[off:gsoEnd]); err != nil {
						return err
					}
				} else {
					return fmt.Errorf("udp gso send: %w", err)
				}
			}
			off = gsoEnd
			copyStart = off
		}
		if copyStart < k {
			if err := writeBatchMessages(ctx, udp, msgs[copyStart:k]); err != nil {
				return err
			}
		}
		k = 0
		batchStart = time.Now()
		return nil
	}

	for {
		waitTimeout := time.Duration(-1)
		if k > 0 {
			waitTimeout = time.Until(batchStart.Add(maxHold))
			if waitTimeout < 0 {
				waitTimeout = 0
			}
		}
		if err := waitFD(int32(tun.fd), unix.POLLIN, waitTimeout); err != nil {
			if ctx.Err() != nil {
				return flushPackets()
			}
			return fmt.Errorf("tun poll: %w", err)
		}
		if ctx.Err() != nil {
			return flushPackets()
		}

		for k < N {
			n, err := tun.ReadNB(readBufs[k][:linkMTU])
			if err != nil {
				if ctx.Err() != nil {
					return flushPackets()
				}
				return fmt.Errorf("tun read: %w", err)
			}
			if n == 0 {
				break
			}
			if n > effMTU {
				slog.Warn("drop oversized inner packet", "len", n, "eff_mtu", effMTU, "link_mtu", linkMTU)
				continue
			}
			pkt := readBufs[k][:n]

			dst, ok := ipv4Dst(pkt)
			if !ok {
				continue
			}
			endpoint, ok := pm.lookup(dst)
			if !ok {
				continue
			}

			// Копирующий путь (батч).
			msgs[k].Buffers[0] = pkt
			msgs[k].Addr = endpoint.udpAddr
			packets[k] = txPacket{buf: pkt, endpoint: endpoint}
			k++

			now := time.Now()
			if udp.inWarmup(now) || k >= pktLimit || !now.Before(batchStart.Add(maxHold)) {
				break
			}
		}

		if err := flushPackets(); err != nil {
			return err
		}
	}
}

//
// ============================ Вспомогательные =========================
//

// prewarmEndpoints — прогрев пиров + явная проверка недоступности.
// Вход: udp, pm. Выход: нет.
func prewarmEndpoints(udp *udpState, pm *peerMap) {
	eps := pm.endpoints()
	if len(eps) == 0 {
		return
	}
	const shots = 2
	msgs := make([]ipv4.Message, 0, len(eps)*shots)

	for _, endpoint := range eps {
		// пассивный прогрев (ARP/NAT/cache)
		for i := 0; i < shots; i++ {
			msgs = append(msgs, ipv4.Message{Buffers: [][]byte{{0}}, Addr: endpoint.udpAddr})
		}
		// активная проверка ICMP Port Unreachable
		func() {
			c, err := net.DialUDP("udp4", nil, endpoint.udpAddr)
			if err != nil {
				udp.notePeerUnavailable(endpoint.key, "warmup", "dial_error", err)
				return
			}
			defer c.Close()
			_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			if _, werr := c.Write([]byte{0}); werr != nil {
				udp.notePeerUnavailable(endpoint.key, "warmup", "send_error", werr)
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			var b [1]byte
			if _, rerr := c.Read(b[:]); isConnRefused(rerr) {
				udp.notePeerUnavailable(endpoint.key, "warmup", "icmp_port_unreachable", rerr)
			}
		}()
	}
	for off := 0; off < len(msgs); {
		n, _ := udp.pc.WriteBatch(msgs[off:], 0)
		if n <= 0 {
			break
		}
		off += n
	}
}

// isConnRefused — true, если ошибка соответствует ECONNREFUSED.
// Вход: err. Выход: bool.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	var se syscall.Errno
	if errors.As(err, &se) && se == syscall.ECONNREFUSED {
		return true
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		return isConnRefused(ne.Err)
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}
