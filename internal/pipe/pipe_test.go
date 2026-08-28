//go:build linux

package pipe

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestGROSegmentation — нарезка coalesced-датаграммы: равные сегменты, хвост короче,
// один сегмент, границы. Оракул — арифметика (число сегментов, длины, непрерывность).
func TestGROSegmentation(t *testing.T) {
	cases := []struct{ ln, gso int }{
		{9000, 1500},  // ровно 6 равных сегментов
		{10000, 1500}, // 6 полных + хвост 1000
		{1500, 1500},  // ровно один сегмент
		{1501, 1500},  // один полный + хвост 1 байт
		{8972, 8972},  // jumbo, один сегмент
		{65507, 1500}, // максимальная UDP-датаграмма
		{3, 1},        // сегменты по байту
	}
	for _, tc := range cases {
		var segs [][2]int
		for off := 0; off < tc.ln; {
			end := groSegEnd(off, tc.ln, tc.gso)
			segs = append(segs, [2]int{off, end})
			off = end
		}
		wantN := (tc.ln + tc.gso - 1) / tc.gso
		if len(segs) != wantN {
			t.Fatalf("ln=%d gso=%d: сегментов %d, ожидалось %d", tc.ln, tc.gso, len(segs), wantN)
		}
		for j, s := range segs {
			if j == 0 && s[0] != 0 {
				t.Fatalf("ln=%d gso=%d: первый сегмент начинается с %d", tc.ln, tc.gso, s[0])
			}
			if j > 0 && s[0] != segs[j-1][1] {
				t.Fatalf("ln=%d gso=%d: разрыв между сегментами %d и %d", tc.ln, tc.gso, j-1, j)
			}
			wantLen := tc.gso
			if j == len(segs)-1 {
				wantLen = tc.ln - tc.gso*(wantN-1)
			}
			if got := s[1] - s[0]; got != wantLen {
				t.Fatalf("ln=%d gso=%d: сегмент %d длины %d, ожидалось %d", tc.ln, tc.gso, j, got, wantLen)
			}
		}
		if segs[len(segs)-1][1] != tc.ln {
			t.Fatalf("ln=%d gso=%d: последний сегмент кончается на %d", tc.ln, tc.gso, segs[len(segs)-1][1])
		}
	}
}

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

// TestGroSegmentSize — извлечение размера сегмента из cmsg и отказ на мусоре.
func TestGroSegmentSize(t *testing.T) {
	if got := groSegmentSize(buildGROCMsg(1500)); got != 1500 {
		t.Fatalf("groSegmentSize = %d, ожидалось 1500", got)
	}
	if got := groSegmentSize(buildGROCMsg(8972)); got != 8972 {
		t.Fatalf("groSegmentSize = %d, ожидалось 8972", got)
	}
	if got := groSegmentSize(nil); got != 0 {
		t.Fatalf("groSegmentSize(nil) = %d, ожидалось 0", got)
	}
	if got := groSegmentSize([]byte{1, 2, 3}); got != 0 {
		t.Fatalf("groSegmentSize(мусор) = %d, ожидалось 0", got)
	}
	// cmsg другого типа не должен распознаваться как GRO
	oob := make([]byte, unix.CmsgSpace(2))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.IPPROTO_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):unix.CmsgLen(0)+2], 1500)
	if got := groSegmentSize(oob); got != 0 {
		t.Fatalf("groSegmentSize(UDP_SEGMENT) = %d, ожидалось 0", got)
	}
}

// mkIPv4Pkt — минимальный IPv4-заголовок с заданными src/dst для тестов flowIndex.
func mkIPv4Pkt(src, dst [4]byte) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	return pkt
}

// TestFlowIndex — детерминизм, границы диапазона, одна очередь.
func TestFlowIndex(t *testing.T) {
	pktA := mkIPv4Pkt([4]byte{10, 10, 0, 1}, [4]byte{10, 10, 0, 2})
	pktB := mkIPv4Pkt([4]byte{10, 10, 0, 3}, [4]byte{10, 10, 0, 9})
	for _, n := range []int{1, 2, 4, 8, 64} {
		first := flowIndex(pktA, n)
		if first < 0 || first >= n {
			t.Fatalf("n=%d: индекс %d вне диапазона", n, first)
		}
		for i := 0; i < 16; i++ {
			if got := flowIndex(pktA, n); got != first {
				t.Fatalf("n=%d: один flow дал %d и %d — хэш недетерминирован", n, first, got)
			}
		}
		if got := flowIndex(pktB, n); got < 0 || got >= n {
			t.Fatalf("n=%d: индекс другого flow %d вне диапазона", n, got)
		}
	}
	if got := flowIndex(pktA, 1); got != 0 {
		t.Fatalf("n=1: индекс %d, ожидалось 0", got)
	}
}
