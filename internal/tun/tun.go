//go:build linux

// Package tun — открытие и настройка TUN (чистый L3: IFF_NO_PI) и маршруты через netlink.
package tun

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	netlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"l3overlay/internal/sysutil"
)

// ioctl константы для TUN.
const (
	iffTUN        = 0x0001
	iffNO_PI      = 0x1000
	iffMULTIQueue = 0x0100
	IFNAMSIZ      = 16
	TUNSETIFF     = 0x400454ca
)

const tunWriteRetryWait = 250 * time.Microsecond

// ifreq — аргумент ioctl(TUNSETIFF).
type ifreq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

// Device — одна очередь TUN (один fd).
type Device struct {
	FD int // файловый дескриптор /dev/net/tun
}

// Bundle — один TUN интерфейс с одной или несколькими очередями.
type Bundle struct {
	Name      string
	Queues    []*Device
	closeOnce sync.Once
}

// Open — открыть TUN интерфейс с заданным числом очередей (IFF_NO_PI).
// Вход: name, queueCount. Выход: *Bundle или ошибка.
func Open(name string, queueCount int) (*Bundle, error) {
	flags := uint16(iffTUN | iffNO_PI)
	if queueCount > 1 {
		flags |= iffMULTIQueue
	}
	bundle := &Bundle{Name: name, Queues: make([]*Device, 0, queueCount)}
	for i := 0; i < queueCount; i++ {
		tun, err := openTUNQueue(name, flags)
		if err != nil {
			_ = bundle.Close()
			return nil, err
		}
		bundle.Queues = append(bundle.Queues, tun)
	}
	return bundle, nil
}

// openTUNQueue — открыть /dev/net/tun и привязать одну очередь интерфейса.
// Вход: name, flags. Выход: *Device или ошибка.
func openTUNQueue(name string, flags uint16) (*Device, error) {
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
	return &Device{FD: fd}, nil
}

// ReadNB — неблокирующее чтение L3-пакета из очереди TUN.
// Вход: p — буфер (вмещает linkMTU). Выход: длина L3; 0 при EAGAIN; ошибка при сбое.
func (t *Device) ReadNB(p []byte) (int, error) {
	n, err := syscall.Read(t.FD, p)
	if sysutil.IsWouldBlockErr(err) {
		return 0, nil
	}
	return n, err
}

// WriteL3 — запись L3-пакета в очередь TUN.
// Вход: pkt — L3 пакет. Выход: число записанных байт или ошибка.
func (t *Device) WriteL3(pkt []byte) (int, error) {
	return syscall.Write(t.FD, pkt)
}

// WriteL3Context — записать L3-пакет в TUN, дождавшись writable при EAGAIN.
// Вход: ctx, pkt, waitCounter. Выход: ошибка записи или nil.
func (t *Device) WriteL3Context(ctx context.Context, pkt []byte, waitCounter *atomic.Uint64) error {
	for {
		n, err := syscall.Write(t.FD, pkt)
		if err == nil {
			if n != len(pkt) {
				return errors.New("short tun write")
			}
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if sysutil.IsWouldBlockErr(err) {
			if waitCounter != nil {
				waitCounter.Add(1)
			}
			if err := sysutil.WaitFD(int32(t.FD), unix.POLLOUT, tunWriteRetryWait); err != nil {
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
func (t *Bundle) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		for _, q := range t.Queues {
			if err := syscall.Close(q.FD); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}

// Configure — поднять интерфейс, адрес/MTU, при необходимости маршрут.
// Вход: name, cidr, linkMTU, addRoute. Выход: фактический MTU линка или ошибка.
func Configure(name, cidr string, linkMTU int, addRoute bool) (int, error) {
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
	link, err = netlink.LinkByName(name)
	if err != nil {
		return 0, errors.New("link re-read: " + err.Error())
	}
	return link.Attrs().MTU, nil
}

// AddGrayRoutes — добавить маршруты доп. подсетей в TUN.
// В вход: tunName, список CIDR. Выход: ошибка при парсинге/системных вызовах.
func AddGrayRoutes(tunName string, cidrs []string) error {
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
