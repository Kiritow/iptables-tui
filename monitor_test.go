package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func ipv4TCP() []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 60)
	binary.BigEndian.PutUint16(b[4:], 1234)
	b[8], b[9] = 64, 6
	copy(b[12:], []byte{10, 0, 0, 1})
	copy(b[16:], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[20:], 40000)
	binary.BigEndian.PutUint16(b[22:], 22)
	b[33] = 0x02 // SYN
	return b
}

func TestDecodePacket(t *testing.T) {
	pi := decodePacket(ipv4TCP())
	if pi.Version != 4 || pi.Src.String() != "10.0.0.1" || pi.Dst.String() != "10.0.0.2" || pi.SPort != 40000 ||
		pi.DPort != 22 || pi.TCPFlags != "SYN" || pi.TotalLen != 60 || pi.ID != 1234 || pi.protoName() != "TCP" {
		t.Errorf("ipv4 tcp: %+v", pi)
	}

	// IPv6 + hop-by-hop options + UDP
	v6 := make([]byte, 40+8+8)
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:], 16)
	v6[6], v6[7] = 0, 64 // next header: hop-by-hop
	v6[23], v6[39] = 1, 2
	v6[40], v6[41] = 17, 0 // hop-by-hop: next UDP, length 8 bytes
	binary.BigEndian.PutUint16(v6[48:], 546)
	binary.BigEndian.PutUint16(v6[50:], 547)
	pi = decodePacket(v6)
	if pi.Version != 6 || pi.Proto != 17 || pi.SPort != 546 || pi.DPort != 547 || pi.Src.String() != "::1" || pi.TotalLen != 56 {
		t.Errorf("ipv6 udp: %+v", pi)
	}

	// IPv6 non-first fragment: no ports
	fr := make([]byte, 40+8+8)
	fr[0], fr[6] = 0x60, 44
	fr[40] = 6
	binary.BigEndian.PutUint16(fr[42:], 185<<3)
	pi = decodePacket(fr)
	if !pi.Frag || pi.Proto != 6 || pi.SPort != -1 {
		t.Errorf("ipv6 fragment: %+v", pi)
	}

	// truncated and garbage input must not panic
	for _, b := range [][]byte{nil, {0x45}, ipv4TCP()[:21], {0x4f, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		append([]byte{0x60}, make([]byte, 39)...), {0x60, 0, 0, 0, 0, 0, 0, 0}, {0xff, 1, 2}} {
		_ = decodePacket(b)
	}
	b := append([]byte{0x60}, make([]byte, 39)...)
	b[6] = 0 // hop-by-hop header missing
	if pi := decodePacket(b); pi.SPort != -1 {
		t.Errorf("truncated ext header: %+v", pi)
	}
}

func TestParseNFLOGMessage(t *testing.T) {
	payload := ipv4TCP()
	ts := make([]byte, 16)
	binary.BigEndian.PutUint64(ts, 1700000000)
	binary.BigEndian.PutUint64(ts[8:], 500000)
	msg := nlMsg(nfnlSubsysULOG<<8|nfulnlMsgPacket, 0, 0, 2, 100,
		nlAttr(nfulaPacketHdr, []byte{8, 0, 1, 0}),
		nlAttr(nfulaMark, be32(0x10)),
		nlAttr(nfulaTimestamp, ts),
		nlAttr(nfulaPrefix, []byte("iptui: \x00")),
		nlAttr(nfulaPayload, payload))
	msgs := splitNL(append(msg, 1, 2, 3)) // trailing garbage is ignored
	if len(msgs) != 1 || msgs[0].typ != nfnlSubsysULOG<<8|nfulnlMsgPacket {
		t.Fatalf("msgs=%+v", msgs)
	}
	c := &nflogConn{ifnames: map[uint32]string{}}
	p := c.parsePacket(msgs[0].data)
	if p.Group != 100 || p.Hook != 1 || p.Mark != 0x10 || p.Prefix != "iptui: " || p.Time.Unix() != 1700000000 ||
		!bytes.Equal(p.Payload, payload) || p.Info.DPort != 22 {
		t.Errorf("packet=%+v", p)
	}
	if s := p.summary(); !strings.Contains(s, "10.0.0.1:40000 -> 10.0.0.2:22 SYN") || !strings.Contains(s, `"iptui: "`) {
		t.Errorf("summary=%q", s)
	}
	// a bogus attribute length must not panic
	_ = c.parsePacket([]byte{2, 0, 0, 100, 0xff, 0xff, 9, 0, 1, 2})
}

// real output of xtables-monitor --trace (steps of different packets interleave)
const xtmSample = `PACKET: 2 6bf9b106 OUT=lo SRC=127.0.0.1 DST=127.0.0.1 LEN=60 TOS=0x0 TTL=64 ID=54916 DF SPORT=55982 DPORT=80 SYN 
 TRACE: 2 6bf9b106 raw:OUTPUT:rule:0x2:CONTINUE  iptables -t raw -A OUTPUT -p tcp -j TRACE
 TRACE: 2 6bf9b106 raw:OUTPUT:policy:ACCEPT 
PACKET: 2 6bf9b106 OUT=lo SRC=127.0.0.1 DST=127.0.0.1 LEN=60 TOS=0x0 TTL=64 ID=54916 DF SPORT=55982 DPORT=80 SYN 
 TRACE: 2 6bf9b106 filter:OUTPUT:rule:0x5:JUMP:CHK  iptables -t filter -A OUTPUT -p tcp -j CHK
 TRACE: 2 6bf9b106 filter:CHK:rule:0x3:0xfffffffb  iptables -t filter -A CHK -p tcp -m tcp --dport 80 -j RETURN
PACKET: 2 35c82d39 OUT=lo SRC=127.0.0.1 DST=127.0.0.1 LEN=40 TOS=0x0 TTL=64 ID=0 DF SPORT=80 DPORT=55982 ACK RST 
 TRACE: 2 35c82d39 raw:OUTPUT:rule:0x2:CONTINUE  iptables -t raw -A OUTPUT -p tcp -j TRACE
 TRACE: 2 35c82d39 filter:OUTPUT:policy:ACCEPT 
 TRACE: 2 6bf9b106 filter:OUTPUT:rule:0x6:DROP  iptables -t filter -A OUTPUT -p tcp -m tcp --dport 80 -j REJECT --reject-with tcp-reset
PACKET: 10 0f397214 OUT=lo SRC=::1 DST=::1 LEN=84 TC=0 HOPLIMIT=64 FLOWLBL=878655 
 TRACE: 10 0f397214 raw:OUTPUT:policy:ACCEPT
garbage line`

func TestTraceGrouping(t *testing.T) {
	m := &monitor{kind: monTRACE, notify: make(chan struct{}, 1), byKey: map[string]*monItem{}}
	for _, l := range strings.Split(xtmSample, "\n") {
		m.xtmLine(l)
	}
	if len(m.items) != 3 {
		t.Fatalf("items=%d", len(m.items))
	}
	first := m.items[0].trace
	if len(first.Steps) != 5 || first.Family != V4 {
		t.Fatalf("first trace: %+v", first)
	}
	if s := first.Steps[2]; s.Table != "filter" || s.Chain != "OUTPUT" || s.Type != "rule" || s.Verdict != "JUMP:CHK" ||
		s.Rule != "iptables -t filter -A OUTPUT -p tcp -j CHK" {
		t.Errorf("jump step: %+v", s)
	}
	if s := first.Steps[3]; s.Verdict != "RETURN" {
		t.Errorf("return step: %+v", s)
	}
	if v, _ := first.verdict(); v != "filter:OUTPUT DROP" {
		t.Errorf("verdict=%q", v)
	}
	if !strings.Contains(m.items[0].summary, "127.0.0.1:55982 -> 127.0.0.1:80 SYN  => filter:OUTPUT DROP  (5 steps)") {
		t.Errorf("summary=%q", m.items[0].summary)
	}
	if v, _ := m.items[1].trace.verdict(); v != "filter:OUTPUT ACCEPT" {
		t.Errorf("second verdict=%q", v)
	}
	if m.items[2].trace.Family != V6 {
		t.Errorf("third family=%v", m.items[2].trace.Family)
	}
}

func TestKmsgTrace(t *testing.T) {
	m := &monitor{kind: monTRACE, notify: make(chan struct{}, 1), byKey: map[string]*monItem{}}
	lines := []string{
		"TRACE: raw:PREROUTING:policy:2 IN=eth0 OUT= MAC=00:11 SRC=10.0.0.1 DST=10.0.0.2 LEN=60 ID=7 PROTO=TCP SPT=1000 DPT=22 SYN",
		"TRACE: filter:INPUT:rule:3 IN=eth0 OUT= MAC=00:11 SRC=10.0.0.1 DST=10.0.0.2 LEN=60 ID=7 PROTO=TCP SPT=1000 DPT=22 SYN",
		"TRACE: raw:PREROUTING:policy:2 IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 LEN=60 ID=8 PROTO=TCP SPT=1000 DPT=22 ACK",
		"not a trace",
	}
	for _, l := range lines {
		m.kmsgLine(l)
	}
	if len(m.items) != 2 || len(m.items[0].trace.Steps) != 2 || m.items[0].trace.Steps[1].RuleNum != 3 {
		t.Fatalf("items=%d %+v", len(m.items), m.items[0].trace)
	}
	if !strings.Contains(m.items[0].summary, "TCP    10.0.0.1:1000 -> 10.0.0.2:22 SYN") {
		t.Errorf("summary=%q", m.items[0].summary)
	}
}

func TestMonitorTrim(t *testing.T) {
	m := &monitor{notify: make(chan struct{}, 1), byKey: map[string]*monItem{}}
	for i := 0; i < monMax*2; i++ {
		m.addLocked(&monItem{})
	}
	if len(m.items) > monMax+monMax/10 || m.total != monMax*2 {
		t.Errorf("items=%d total=%d", len(m.items), m.total)
	}
}

func TestPcap(t *testing.T) {
	p := &nflogPacket{Payload: ipv4TCP()[:28], Info: decodePacket(ipv4TCP())}
	path := t.TempDir() + "/x.pcap"
	n, err := writePcap(path, []*nflogPacket{p, {Payload: []byte{1, 2}}})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	data, _ := readFile(path)
	if len(data) != 24+16+28 || binary.LittleEndian.Uint32(data[20:]) != 101 ||
		binary.LittleEndian.Uint32(data[24+8:]) != 28 || binary.LittleEndian.Uint32(data[24+12:]) != 60 {
		t.Errorf("pcap bytes: % x", data[:40])
	}
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

func TestVersionHelpers(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.0.1": false, "v0.0.0-20261031024500-abcdef123456": true,
		"v0.0.2-0.20261031024500-abcdef123456+dirty": true, "v1.2.3+dirty": false,
	} {
		if got := isPseudoVersion(v); got != want {
			t.Errorf("isPseudoVersion(%q) = %v", v, got)
		}
	}
	// lines that fit keep their column alignment
	if got := wrapText("  w         watch", 40); len(got) != 1 || got[0] != "  w         watch" {
		t.Errorf("wrapText = %q", got)
	}
}
