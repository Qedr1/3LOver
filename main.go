//go:build linux

// L3-оверлей через TUN и UDP. IPv4-only. Без шифрования.
// TUN: чистый L3 (IFF_NO_PI).
//
// Производительность:
// - RX: ipv4.PacketConn.ReadBatch (UDP_GRO) → запись в TUN.
// - TX: чтение из TUN → отправка UDP: копирующий батч WriteBatch или GSO sendmsg.
//
// Логи недоступности пира: warmup и tx, троттлинг 5с/peer.

package main

import (
	"context"
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
	"strings"
	"sync"
	"syscall"
	"time"

	netlink "github.com/vishvananda/netlink"

	"l3overlay/internal/config"
	"l3overlay/internal/peers"
	"l3overlay/internal/pipe"
	"l3overlay/internal/sysutil"
	"l3overlay/internal/tun"
	"l3overlay/internal/udp"
)

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

// =============================== main ================================
//

var cfgPath = flag.String("config", "overlay.toml", "путь к конфигу TOML")

// main — инициализация, прогрев, запуск конвейеров.
// Вход: флаги командной строки. Выход: код завершения процесса (через os.Exit).
func main() {
	flag.Parse()
	runtime.GOMAXPROCS(0)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config load", "err", err)
		os.Exit(1)
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: config.ParseLevel(cfg.Log.Level)})
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

	pm := peers.NewMap()
	if err := pm.LoadFromTOML(cfg.Map.Path); err != nil {
		slog.Error("map load", "err", err)
		os.Exit(1)
	}

	// Открыть TUN (чистый L3).
	tunB, err := tun.Open(cfg.Tun.Name, cfg.Tun.Queues)
	if err != nil {
		slog.Error("tun open", "err", err)
		os.Exit(1)
	}
	defer tunB.Close()

	// Контекст завершения.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := startPprofServer(ctx, cfg.Debug.PprofListen); err != nil {
		slog.Error("pprof start", "listen", cfg.Debug.PprofListen, "err", err)
		os.Exit(1)
	}

	// Настройка линка/адреса/маршрутов.
	reqLinkMTU := cfg.Tun.LinkMTU
	linkMTU, err := tun.Configure(cfg.Tun.Name, cfg.Tun.Addr, reqLinkMTU, cfg.Tun.AddRoute)
	if err != nil {
		slog.Error("tun configure", "err", err)
		os.Exit(1)
	}
	if err := tun.AddGrayRoutes(cfg.Tun.Name, cfg.Tun.GrayRoutes); err != nil {
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
	udpB, err := udp.NewBundle(cfg.Transport.Listen, cfg.Transport.Listeners,
		cfg.Transport.UDPRcv, cfg.Transport.UDPSnd, cfg.Transport.ReusePort,
		false, cfg.Transport.ZCMinBytes)
	if err != nil {
		slog.Error("udp listen", "err", err)
		os.Exit(1)
	}
	defer udpB.Close()
	udpB.Primary.SetWarmupUntil(time.Now().Add(cfg.Batch.Warmup))

	// Период опроса error-queue = min(hold, 20ms).
	errqTick := cfg.Batch.Hold
	if errqTick <= 0 || errqTick > 20*time.Millisecond {
		errqTick = 20 * time.Millisecond
	}
	udpB.Primary.StartErrMonitor(ctx, pm, errqTick)

	// Адаптивные батчи от фактических буферов сокета, но с жёстким upper bound,
	// чтобы не устраивать локальные microbursts.
	const maxRXBatchBytes = 512 << 10
	const maxRXBurstPackets = 64
	const maxTXBatchBytes = 64 << 10
	const maxTXBurstPackets = 4
	targetBatchBytesRX := sysutil.Clamp(udpB.Primary.RcvSz/4, effMTU, maxRXBatchBytes)
	targetBatchBytesTX := sysutil.Clamp(udpB.Primary.SndSz/4, effMTU, maxTXBatchBytes)
	perListenerBatchBytesRX := sysutil.Clamp(targetBatchBytesRX/len(udpB.Listeners), effMTU, 2<<20)
	pktLimitRX := sysutil.Clamp(perListenerBatchBytesRX/effMTU, 1, maxRXBurstPackets)
	pktLimitTX := sysutil.Clamp(targetBatchBytesTX/effMTU, 1, maxTXBurstPackets)
	perWorkerPktLimitTX := sysutil.Clamp(pktLimitTX/len(tunB.Queues), 1, 2048)
	rxQueueDepth := sysutil.Clamp(pktLimitRX*16, 512, 8192)
	txMaxHold := cfg.Batch.Hold
	if txMaxHold <= 0 || txMaxHold > 25*time.Microsecond {
		txMaxHold = 25 * time.Microsecond
	}

	slog.Debug("Starting...",
		"listen", cfg.Transport.Listen,
		"udp_listeners", len(udpB.Listeners), "reuse_port", cfg.Transport.ReusePort,
		"udp_rbuf_req", cfg.Transport.UDPRcv, "udp_wbuf_req", cfg.Transport.UDPSnd,
		"udp_rbuf_act", udpB.Primary.RcvSz, "udp_wbuf_act", udpB.Primary.SndSz,
		"batch_bytes_rx", targetBatchBytesRX, "batch_bytes_tx", targetBatchBytesTX,
		"batch_bytes_rx_listener", perListenerBatchBytesRX,
		"rx_queue_depth", rxQueueDepth,
		"pkt_limit_rx_listener", pktLimitRX, "pkt_limit_tx_total", pktLimitTX,
		"pkt_limit_tx_worker", perWorkerPktLimitTX,
		"cfg_mtu", cfg.Tun.MTU, "link_mtu", linkMTU, "eff_mtu", effMTU,
		"hold", cfg.Batch.Hold, "tx_hold", txMaxHold, "warmup", cfg.Batch.Warmup,
		"udp_gso", udpB.Primary.TxGSOEnabled(),
		"udp_gro", udpB.Primary.Gro,
		"zerocopy", udpB.Primary.ZeroCopy(),
		"tun", cfg.Tun.Name, "tun_queues", len(tunB.Queues),
	)

	slog.Info("Service started", "tun", cfg.Tun.Name, "tun_queues", len(tunB.Queues))

	// Прогрев пиров.
	pipe.PrewarmEndpoints(udpB.Primary, pm)

	var wg sync.WaitGroup
	errCh := make(chan error, len(tunB.Queues)+len(udpB.Listeners)+16)
	stats := &pipe.Stats{}

	// Буферы RX: под coalesced-датаграммы UDP_GRO нужен приём до 64KiB.
	rxBufSize := effMTU
	if udpB.Primary.Gro {
		rxBufSize = 64 << 10
	}
	rxPool := pipe.NewBufferPool(rxBufSize)
	ingresses := make([]*pipe.Ingress, len(tunB.Queues))
	for i, queue := range tunB.Queues {
		ingresses[i] = pipe.NewIngress(queue, rxPool, rxQueueDepth)
	}

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

	for idx, ing := range ingresses {
		idx := idx
		ing := ing
		workerName := fmt.Sprintf("rx-write[%d]", idx)
		runWorker(workerName, func() error {
			return ing.WriteLoop(ctx)
		})
	}
	for idx, rxUDP := range udpB.Listeners {
		idx := idx
		rxUDP := rxUDP
		workerName := fmt.Sprintf("rx[%d]", idx)
		runWorker(workerName, func() error {
			return pipe.RxReadLoop(ctx, rxUDP, ingresses, rxPool, effMTU, rxBufSize, pktLimitRX, stats)
		})
	}
	for idx, queue := range tunB.Queues {
		idx := idx
		queue := queue
		workerName := fmt.Sprintf("tx[%d]", idx)
		runWorker(workerName, func() error {
			return pipe.TxLoop(ctx, udpB.Primary, pm, queue, linkMTU, effMTU, perWorkerPktLimitTX, txMaxHold, stats)
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

	udpB.Close()
	_ = tunB.Close()
	wg.Wait()
	for _, ing := range ingresses {
		ing.LogStats()
	}
	stats.Log()
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
