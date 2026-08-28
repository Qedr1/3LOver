//go:build linux

// Package config — конфигурация сервиса (TOML) с дефолтами и уровень логирования.
package config

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

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
		Hold   time.Duration `toml:"hold"`   // шаг опроса error-queue и верхняя граница TX-удержания (TX клампится до 25µs); 0 → 5ms
		Warmup time.Duration `toml:"warmup"` // длительность прогрева; 0 → 2s
	} `toml:"batch"`
	Log struct {
		Level string `toml:"level"` // debug|info|warn|error; "" → info
	} `toml:"log"`
	Debug struct {
		PprofListen string `toml:"pprof_listen"` // HTTP pprof bind; "" → disabled
	} `toml:"debug"`
}

// Load — загрузка TOML и дефолты.
// Вход: путь к файлу. Выход: Config или ошибка.
func Load(path string) (Config, error) {
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

// ParseLevel — строка уровня → slog.Level.
// Вход: строка уровня. Выход: slog.Level.
func ParseLevel(s string) slog.Level {
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
