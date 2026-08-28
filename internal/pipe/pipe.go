//go:build linux

// Package pipe — RX/TX конвейеры: UDP ReadBatch → TUN, TUN → UDP (WriteBatch / GSO sendmsg).
package pipe

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

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"l3overlay/internal/peers"
	"l3overlay/internal/sysutil"
	"l3overlay/internal/tun"
	"l3overlay/internal/udp"
)

// buffer — буфер датаграммы с подсчётом ссылок: сегменты одной GRO-датаграммы делят один буфер.
type buffer struct {
	data []byte
	refs atomic.Int32
}

// release — освободить одну ссылку; последняя возвращает буфер в pool.
// Вход: pool. Выход: нет.
func (b *buffer) release(pool *sync.Pool) {
	if b.refs.Add(-1) == 0 {
		b.data = b.data[:cap(b.data)]
		pool.Put(b)
	}
}

// packet — inner-пакет (сегмент буфера) для передачи от UDP reader к TUN writer.
type packet struct {
	seg   []byte
	owner *buffer
}

// txPacket — inner-пакет и его уже разрешённый UDP endpoint для TX flush.
type txPacket struct {
	buf      []byte
	endpoint peers.Endpoint
}

// IngressStats — счётчики давления на RX очередь и записи в TUN.
type IngressStats struct {
	enqueued       atomic.Uint64
	written        atomic.Uint64
	queueWaits     atomic.Uint64
	queueHighWater atomic.Uint64
	tunWriteWaits  atomic.Uint64
}

// Ingress — bounded queue между UDP readers и одним TUN writer (один на очередь TUN).
type Ingress struct {
	packets chan packet
	pool    *sync.Pool
	tun     *tun.Device
	stats   IngressStats
}

// Stats — счётчики дропов и GRO на RX/TX путях.
type Stats struct {
	UnknownDst     atomic.Uint64
	OversizedInner atomic.Uint64
	RxInvalid      atomic.Uint64
	GroDatagrams   atomic.Uint64
	GroSegments    atomic.Uint64
}

// NewBufferPool — создать pool буферов датаграмм заданного размера.
// Вход: размер буфера. Выход: *sync.Pool.
func NewBufferPool(size int) *sync.Pool {
	return &sync.Pool{New: func() any { return &buffer{data: make([]byte, size)} }}
}

// NewIngress — создать RX очередь и TUN writer state для одной очереди TUN.
// Вход: t, общий pool буферов, queueDepth. Выход: *Ingress.
func NewIngress(t *tun.Device, pool *sync.Pool, queueDepth int) *Ingress {
	return &Ingress{
		packets: make(chan packet, queueDepth),
		pool:    pool,
		tun:     t,
	}
}

// noteQueueDepth — обновить high-water mark RX очереди.
// Вход: depth. Выход: нет.
func (r *Ingress) noteQueueDepth(depth int) {
	for {
		old := r.stats.queueHighWater.Load()
		if uint64(depth) <= old || r.stats.queueHighWater.CompareAndSwap(old, uint64(depth)) {
			return
		}
	}
}

// enqueuePacket — передать владение пакетом в RX очередь для TUN writer.
// Вход: ctx, pkt (ссылка owner переходит очереди). Выход: ошибка ctx или nil.
func (r *Ingress) enqueuePacket(ctx context.Context, pkt packet) error {
	select {
	case r.packets <- pkt:
		r.stats.enqueued.Add(1)
		r.noteQueueDepth(len(r.packets))
		return nil
	default:
		r.stats.queueWaits.Add(1)
	}

	select {
	case r.packets <- pkt:
		r.stats.enqueued.Add(1)
		r.noteQueueDepth(len(r.packets))
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// drainPackets — освободить буферы из очереди.
// Вход: нет. Выход: нет.
func (r *Ingress) drainPackets() {
	for {
		select {
		case pkt := <-r.packets:
			pkt.owner.release(r.pool)
		default:
			return
		}
	}
}

// WriteLoop — отдельный writer RX очереди в TUN.
// Вход: ctx. Выход: ошибка или nil.
func (r *Ingress) WriteLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			r.drainPackets()
			return nil
		case pkt := <-r.packets:
			err := r.tun.WriteL3Context(ctx, pkt.seg, &r.stats.tunWriteWaits)
			pkt.owner.release(r.pool)
			if err != nil {
				if ctx.Err() != nil {
					r.drainPackets()
					return nil
				}
				r.drainPackets()
				return fmt.Errorf("tun write: %w", err)
			}
			r.stats.written.Add(1)
		}
	}
}

// LogStats — записать итоговые счётчики RX очереди.
// Вход: нет. Выход: нет.
func (r *Ingress) LogStats() {
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

// Log — записать итоговые счётчики pipeline.
// Вход: нет. Выход: нет.
func (s *Stats) Log() {
	slog.Info("pipeline stats",
		"unknown_dst", s.UnknownDst.Load(),
		"oversized_inner", s.OversizedInner.Load(),
		"rx_invalid", s.RxInvalid.Load(),
		"gro_datagrams", s.GroDatagrams.Load(),
		"gro_segments", s.GroSegments.Load(),
	)
}

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

// groSegmentSize — извлечь размер сегмента из cmsg UDP_GRO.
// Вход: oob (прочитанные cmsg). Выход: размер сегмента или 0.
func groSegmentSize(oob []byte) int {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for i := range cmsgs {
		if cmsgs[i].Header.Level == unix.IPPROTO_UDP && cmsgs[i].Header.Type == unix.UDP_GRO && len(cmsgs[i].Data) >= 2 {
			return int(binary.NativeEndian.Uint16(cmsgs[i].Data))
		}
	}
	return 0
}

// groSegEnd — конец сегмента [off:end) при нарезке coalesced-датаграммы.
// Вход: off, ln, gso. Выход: end (последний сегмент может быть короче gso).
func groSegEnd(off, ln, gso int) int {
	end := off + gso
	if end > ln {
		end = ln
	}
	return end
}

// flowIndex — детерминированная диспетчеризация inner-пакета по очередям TUN.
// Вход: pkt (валидный IPv4 заголовок), число очередей. Выход: индекс очереди [0..n).
func flowIndex(pkt []byte, n int) int {
	if n <= 1 {
		return 0
	}
	src := binary.BigEndian.Uint32(pkt[12:16])
	dst := binary.BigEndian.Uint32(pkt[16:20])
	h := (src ^ dst) * 2654435761
	return int(h % uint32(n))
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
	endpointKey := packets[start].endpoint.GSOKey
	end := start + 1
	for end < len(packets) && end-start < maxUDPSegments {
		if packets[end].endpoint.GSOKey != endpointKey {
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

// RxReadLoop — приём UDP батчами (с нарезкой UDP_GRO) и постановка inner-пакетов в очереди TUN по flow-hash.
// Вход: ctx, u, ingresses, pool, effMTU, readSize, pktLimit, stats. Выход: ошибка worker или nil.
func RxReadLoop(ctx context.Context, u *udp.State, ingresses []*Ingress, pool *sync.Pool, effMTU, readSize, pktLimit int, stats *Stats) error {
	N := sysutil.Clamp(pktLimit*4, 64, 512)
	msgs := make([]ipv4.Message, N)
	owners := make([]*buffer, N)
	for i := 0; i < N; i++ {
		owners[i] = pool.Get().(*buffer)
		msgs[i].Buffers = [][]byte{owners[i].data[:readSize]}
		if u.Gro {
			msgs[i].OOB = make([]byte, 64)
		}
	}
	defer func() {
		for _, owner := range owners {
			owner.data = owner.data[:cap(owner.data)]
			pool.Put(owner)
		}
	}()

	// freshSlot — заменить переданный в очередь буфер свежим из pool.
	freshSlot := func(i int) {
		owners[i] = pool.Get().(*buffer)
		msgs[i].Buffers = [][]byte{owners[i].data[:readSize]}
	}

	for {
		n, err := u.PC.ReadBatch(msgs, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if sysutil.IsTempRecvErr(err) {
				if u.FD > 0 {
					_ = sysutil.WaitFD(int32(u.FD), unix.POLLIN, time.Millisecond)
				} else {
					time.Sleep(200 * time.Microsecond)
				}
				continue
			}
			return fmt.Errorf("udp read batch: %w", err)
		}
		if n <= 0 {
			continue
		}
		for i := 0; i < n; i++ {
			ln := msgs[i].N
			if ln <= 0 {
				continue
			}
			owner := owners[i]
			gso := 0
			if u.Gro && msgs[i].NN > 0 {
				gso = groSegmentSize(msgs[i].OOB[:msgs[i].NN])
			}
			if gso > 0 && ln > gso {
				// coalesced-датаграмма: режем на inner-сегменты, все делят один буфер.
				nseg := (ln + gso - 1) / gso
				owner.refs.Store(int32(nseg))
				stats.GroDatagrams.Add(1)
				stats.GroSegments.Add(uint64(nseg))
				off := 0
				for j := 0; j < nseg; j++ {
					end := groSegEnd(off, ln, gso)
					seg := owner.data[off:end]
					off = end
					if len(seg) > effMTU {
						stats.RxInvalid.Add(1)
						owner.release(pool)
						continue
					}
					if _, ok := ipv4Dst(seg); !ok {
						stats.RxInvalid.Add(1)
						owner.release(pool)
						continue
					}
					if err := ingresses[flowIndex(seg, len(ingresses))].enqueuePacket(ctx, packet{seg: seg, owner: owner}); err != nil {
						for ; j < nseg; j++ {
							owner.release(pool)
						}
						return nil
					}
				}
				freshSlot(i)
				continue
			}
			if ln > effMTU {
				stats.RxInvalid.Add(1)
				continue
			}
			seg := owner.data[:ln]
			if _, ok := ipv4Dst(seg); !ok {
				stats.RxInvalid.Add(1)
				continue
			}
			owner.refs.Store(1)
			if err := ingresses[flowIndex(seg, len(ingresses))].enqueuePacket(ctx, packet{seg: seg, owner: owner}); err != nil {
				owner.release(pool)
				return nil
			}
			freshSlot(i)
		}
	}
}

// TxLoop — чтение из одной очереди TUN и отправка UDP.
// Вход: ctx, u, pm, t, linkMTU, effMTU, pktLimit, maxHold, stats.
// Выход: ошибка worker или nil.
func TxLoop(ctx context.Context, u *udp.State, pm *peers.Map, t *tun.Device, linkMTU, effMTU, pktLimit int, maxHold time.Duration, stats *Stats) error {
	N := sysutil.Clamp(pktLimit*2, 16, 128)

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
		if !u.TxGSOEnabled() {
			if err := udp.WriteBatchMessages(ctx, u, msgs[:k]); err != nil {
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
				if err := udp.WriteBatchMessages(ctx, u, msgs[copyStart:off]); err != nil {
					return err
				}
			}
			gsoBufs := gsoBuffers[:gsoEnd-off]
			for i := range gsoBufs {
				gsoBufs[i] = packets[off+i].buf
			}
			if err := udp.SendGSOSegments(ctx, u, gsoBufs, packets[off].endpoint.Sock4, gsoOOB); err != nil {
				if !u.TxGSOEnabled() || sysutil.IsTempSendErr(err) {
					if err := udp.WriteBatchMessages(ctx, u, msgs[off:gsoEnd]); err != nil {
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
			if err := udp.WriteBatchMessages(ctx, u, msgs[copyStart:k]); err != nil {
				return err
			}
		}
		k = 0
		batchStart = time.Now()
		return nil
	}

	for {
		// idle-ожидание ограничено, чтобы worker замечал отмену ctx:
		// close(tun.fd) в другом потоке не будит заблокированный ppoll.
		waitTimeout := 250 * time.Millisecond
		if k > 0 {
			waitTimeout = time.Until(batchStart.Add(maxHold))
			if waitTimeout < 0 {
				waitTimeout = 0
			}
		}
		if err := sysutil.WaitFD(int32(t.FD), unix.POLLIN, waitTimeout); err != nil {
			if ctx.Err() != nil {
				return flushPackets()
			}
			return fmt.Errorf("tun poll: %w", err)
		}
		if ctx.Err() != nil {
			return flushPackets()
		}

		for k < N {
			n, err := t.ReadNB(readBufs[k])
			if err != nil {
				if ctx.Err() != nil {
					return flushPackets()
				}
				return fmt.Errorf("tun read: %w", err)
			}
			if n == 0 {
				break
			}
			pkt := readBufs[k][:n]

			if len(pkt) > effMTU {
				stats.OversizedInner.Add(1)
				slog.Warn("drop oversized inner packet", "len", len(pkt), "eff_mtu", effMTU, "link_mtu", linkMTU)
				continue
			}

			dst, ok := ipv4Dst(pkt)
			if !ok {
				continue
			}
			endpoint, ok := pm.Lookup(dst)
			if !ok {
				stats.UnknownDst.Add(1)
				continue
			}

			// Копирующий путь (батч).
			msgs[k].Buffers[0] = pkt
			msgs[k].Addr = endpoint.UDPAddr
			packets[k] = txPacket{buf: pkt, endpoint: endpoint}
			k++

			now := time.Now()
			if u.InWarmup(now) || k >= pktLimit || !now.Before(batchStart.Add(maxHold)) {
				break
			}
		}

		if err := flushPackets(); err != nil {
			return err
		}
	}
}

// PrewarmEndpoints — прогрев пиров + явная проверка недоступности.
// Вход: u, pm. Выход: нет.
func PrewarmEndpoints(u *udp.State, pm *peers.Map) {
	eps := pm.Endpoints()
	if len(eps) == 0 {
		return
	}
	const shots = 2
	msgs := make([]ipv4.Message, 0, len(eps)*shots)

	for _, endpoint := range eps {
		// пассивный прогрев (ARP/NAT/cache)
		for i := 0; i < shots; i++ {
			msgs = append(msgs, ipv4.Message{Buffers: [][]byte{{0}}, Addr: endpoint.UDPAddr})
		}
		// активная проверка ICMP Port Unreachable
		func() {
			c, err := net.DialUDP("udp4", nil, endpoint.UDPAddr)
			if err != nil {
				u.NotePeerUnavailable(endpoint.Key, "warmup", "dial_error", err)
				return
			}
			defer c.Close()
			_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			if _, werr := c.Write([]byte{0}); werr != nil {
				u.NotePeerUnavailable(endpoint.Key, "warmup", "send_error", werr)
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			var b [1]byte
			if _, rerr := c.Read(b[:]); isConnRefused(rerr) {
				u.NotePeerUnavailable(endpoint.Key, "warmup", "icmp_port_unreachable", rerr)
			}
		}()
	}
	for off := 0; off < len(msgs); {
		n, _ := u.PC.WriteBatch(msgs[off:], 0)
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
