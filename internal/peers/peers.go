//go:build linux

// Package peers — мэппинг серый_IP → UDP endpoint под atomic.Value.
package peers

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/BurntSushi/toml"
	"golang.org/x/sys/unix"
)

// peersTOML — формат TOML файла мэппинга пиров.
type peersTOML struct {
	Peers map[string]string `toml:"peers"`
}

// Endpoint — нормализованный IPv4 endpoint и готовые адресные формы для отправки.
type Endpoint struct {
	Key     string
	GSOKey  uint64
	UDPAddr *net.UDPAddr
	Sock4   *unix.SockaddrInet4
}

// Map — неизменяемая карта серый_IP→endpoint под atomic.Value.
type Map struct {
	v atomic.Value // map[uint32]Endpoint
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

// ResolveIPv4Endpoint — нормализовать и заранее подготовить IPv4 UDP endpoint.
// Вход: raw endpoint "host:port". Выход: Endpoint или ошибка.
func ResolveIPv4Endpoint(raw string) (Endpoint, error) {
	addr, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(raw))
	if err != nil {
		return Endpoint{}, err
	}
	if addr == nil || addr.IP == nil {
		return Endpoint{}, errors.New("empty resolved endpoint")
	}
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return Endpoint{}, errors.New("IPv4 endpoint required")
	}
	udpAddr := &net.UDPAddr{IP: append(net.IP(nil), ip4...), Port: addr.Port}
	sock4 := &unix.SockaddrInet4{Port: addr.Port}
	copy(sock4.Addr[:], ip4)
	return Endpoint{
		Key:     net.JoinHostPort(udpAddr.IP.String(), strconv.Itoa(udpAddr.Port)),
		GSOKey:  uint64(rip4(ip4))<<16 | uint64(uint16(addr.Port)),
		UDPAddr: udpAddr,
		Sock4:   sock4,
	}, nil
}

// NewMap — создать пустую атомарную карту.
// Вход: нет. Выход: *Map.
func NewMap() *Map {
	pm := &Map{}
	pm.v.Store(make(map[uint32]Endpoint))
	return pm
}

// LoadFromTOML — загрузить мэппинг и атомарно заменить карту.
// Вход: путь к TOML. Выход: ошибка при парсинге/валидации.
func (pm *Map) LoadFromTOML(path string) error {
	var pf peersTOML
	if _, err := toml.DecodeFile(path, &pf); err != nil {
		return err
	}
	if len(pf.Peers) == 0 {
		return errors.New("empty peers in mapping TOML")
	}
	tmp := make(map[uint32]Endpoint, len(pf.Peers))
	for gray, white := range pf.Peers {
		ip := net.ParseIP(strings.TrimSpace(gray))
		if ip == nil || ip.To4() == nil {
			return errors.New("map: IPv4 required: " + gray)
		}
		endpoint, err := ResolveIPv4Endpoint(white)
		if err != nil {
			return errors.New("map: endpoint invalid for " + gray + ": " + err.Error())
		}
		tmp[rip4(ip)] = endpoint
	}
	pm.v.Store(tmp)
	return nil
}

// Lookup — быстрый поиск endpoint по dst IPv4 без блокировок.
// Вход: dstIPv4 — 4 байта адреса. Выход: endpoint и ok.
func (pm *Map) Lookup(dstIPv4 []byte) (Endpoint, bool) {
	if len(dstIPv4) != 4 {
		return Endpoint{}, false
	}
	key := uint32(dstIPv4[0])<<24 | uint32(dstIPv4[1])<<16 | uint32(dstIPv4[2])<<8 | uint32(dstIPv4[3])
	m := pm.v.Load().(map[uint32]Endpoint)
	endpoint, ok := m[key]
	return endpoint, ok
}

// Endpoints — уникальные endpoints для прогрева.
// Вход: нет. Выход: список уникальных "ip:port".
func (pm *Map) Endpoints() []Endpoint {
	m := pm.v.Load().(map[uint32]Endpoint)
	seen := make(map[string]struct{}, len(m))
	out := make([]Endpoint, 0, len(m))
	for _, endpoint := range m {
		if _, ok := seen[endpoint.Key]; ok {
			continue
		}
		seen[endpoint.Key] = struct{}{}
		out = append(out, endpoint)
	}
	return out
}

// EndpointByIP — найти известный endpoint по IPv4 без порта.
// Вход: ip строкой. Выход: ключ "ip:port", ok.
func (pm *Map) EndpointByIP(ip string) (string, bool) {
	if ip == "" {
		return "", false
	}
	for _, endpoint := range pm.Endpoints() {
		if endpoint.UDPAddr.IP.String() == ip {
			return endpoint.Key, true
		}
	}
	return "", false
}
