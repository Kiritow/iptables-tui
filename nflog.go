package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// nfnetlink_log protocol constants (linux/netfilter/nfnetlink_log.h).
const (
	nfnlSubsysULOG   = 4
	nfulnlMsgPacket  = 0
	nfulnlMsgConfig  = 1
	nfulaCfgCmd      = 1
	nfulaCfgMode     = 2
	nfulaCfgTimeout  = 4
	nfulaCfgQthresh  = 5
	nfulnlCfgCmdBind = 1
	nfulnlCopyPacket = 2

	nfulaPacketHdr = 1
	nfulaMark      = 2
	nfulaTimestamp = 3
	nfulaIfIndev   = 4
	nfulaIfOutdev  = 5
	nfulaPayload   = 9
	nfulaPrefix    = 10
	nfulaUID       = 11
	nfulaGID       = 14

	nflogCopyRange = 2048 // bytes of each packet we ask the kernel for
)

var (
	ne = binary.NativeEndian // netlink headers are host order
	be = binary.BigEndian    // nfnetlink attribute payloads are network order
)

var hookNames = []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}

// nflogPacket is one packet received from an NFLOG group.
type nflogPacket struct {
	Time    time.Time
	Group   uint16
	Hook    int // -1 if unknown
	Prefix  string
	InDev   string
	OutDev  string
	Mark    uint32
	UID     int64 // -1 if absent
	GID     int64
	Payload []byte // starts at the network header, possibly truncated
	Info    pktInfo
}

// pktInfo is what we decode from the network and transport headers.
type pktInfo struct {
	Version  int // 4 or 6; 0 if not IP
	Src, Dst net.IP
	Proto    uint8
	TotalLen int
	TTL      int
	ID       int // IPv4 identification, -1 for IPv6
	Frag     bool
	SPort    int // -1 if none
	DPort    int
	TCPFlags string
	ICMPType int // -1 if none
	ICMPCode int
}

func align4(n int) int { return (n + 3) &^ 3 }

func nlMsg(typ, flags uint16, seq uint32, family uint8, resID uint16, attrs ...[]byte) []byte {
	b := make([]byte, 20)
	b[16], b[17] = family, 0 // nfgenmsg: family, version NFNETLINK_V0
	be.PutUint16(b[18:20], resID)
	for _, a := range attrs {
		b = append(b, a...)
	}
	ne.PutUint32(b[0:4], uint32(len(b)))
	ne.PutUint16(b[4:6], typ)
	ne.PutUint16(b[6:8], flags)
	ne.PutUint32(b[8:12], seq)
	return b
}

func nlAttr(typ uint16, data []byte) []byte {
	b := make([]byte, align4(4+len(data)))
	ne.PutUint16(b[0:2], uint16(4+len(data)))
	ne.PutUint16(b[2:4], typ)
	copy(b[4:], data)
	return b
}

func be32(v uint32) []byte { return be.AppendUint32(nil, v) }

type nlMessage struct {
	typ  uint16
	seq  uint32
	data []byte
}

// splitNL splits a datagram into netlink messages, stopping at anything malformed.
func splitNL(b []byte) []nlMessage {
	var out []nlMessage
	for len(b) >= 16 {
		l := int(ne.Uint32(b[0:4]))
		if l < 16 || l > len(b) {
			break
		}
		out = append(out, nlMessage{typ: ne.Uint16(b[4:6]), seq: ne.Uint32(b[8:12]), data: b[16:l]})
		b = b[min(align4(l), len(b)):]
	}
	return out
}

// parseAttrs parses a flat list of netlink attributes; later duplicates win.
func parseAttrs(b []byte) map[uint16][]byte {
	m := map[uint16][]byte{}
	for len(b) >= 4 {
		l := int(ne.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			break
		}
		m[ne.Uint16(b[2:4])&0x3fff] = b[4:l] // strip NLA_F_NESTED / NLA_F_NET_BYTEORDER
		b = b[min(align4(l), len(b)):]
	}
	return m
}

// nflogConn is a netlink socket bound to one NFLOG group.
type nflogConn struct {
	fd      int
	group   uint16
	stopped atomic.Bool
	ifnames map[uint32]string
}

// openNFLOG binds an NFLOG group. Only one socket can own a group; if
// another program (ulogd, ...) has it, the kernel answers EBUSY.
func openNFLOG(group uint16) (*nflogConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	c := &nflogConn{fd: fd, group: group, ifnames: map[uint32]string{}}
	fail := func(err error) (*nflogConn, error) {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fail(fmt.Errorf("netlink bind: %w", err))
	}
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 8<<20) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8<<20)
	}
	// a receive timeout lets the reader notice stop requests
	tv := syscall.Timeval{Usec: 200000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fail(err)
	}
	if err := c.config(1, nlAttr(nfulaCfgCmd, []byte{nfulnlCfgCmdBind})); err != nil {
		if errors.Is(err, syscall.EBUSY) {
			return fail(fmt.Errorf("NFLOG group %d is already in use by another program (e.g. ulogd); pick another group", group))
		}
		return fail(fmt.Errorf("binding NFLOG group %d: %w", group, err))
	}
	mode := be32(nflogCopyRange)
	mode = append(mode, nfulnlCopyPacket, 0)
	if err := c.config(2, nlAttr(nfulaCfgMode, mode)); err != nil {
		return fail(fmt.Errorf("NFLOG copy mode: %w", err))
	}
	// deliver every packet right away instead of batching
	_ = c.config(3, nlAttr(nfulaCfgQthresh, be32(1)))
	_ = c.config(4, nlAttr(nfulaCfgTimeout, be32(10)))
	return c, nil
}

// config sends a configuration message for the group and waits for the ack.
func (c *nflogConn) config(seq uint32, attrs ...[]byte) error {
	msg := nlMsg(nfnlSubsysULOG<<8|nfulnlMsgConfig, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq,
		syscall.AF_UNSPEC, c.group, attrs...)
	if err := syscall.Sendto(c.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err == syscall.EAGAIN || err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		for _, m := range splitNL(buf[:n]) {
			if m.typ == syscall.NLMSG_ERROR && m.seq == seq && len(m.data) >= 4 {
				if errno := int32(ne.Uint32(m.data[0:4])); errno != 0 {
					return syscall.Errno(-errno)
				}
				return nil
			}
		}
	}
	return errors.New("no answer from the kernel")
}

func (c *nflogConn) stop() { c.stopped.Store(true) }

// run receives packets until stop is called. overrun is called when the
// socket buffer overflowed and the kernel dropped packets.
func (c *nflogConn) run(emit func(*nflogPacket), overrun func()) error {
	defer syscall.Close(c.fd)
	buf := make([]byte, 1<<18)
	for !c.stopped.Load() {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		switch {
		case err == syscall.EAGAIN || err == syscall.EINTR:
			continue
		case err == syscall.ENOBUFS:
			overrun()
			continue
		case err != nil:
			return err
		}
		for _, m := range splitNL(buf[:n]) {
			if m.typ == nfnlSubsysULOG<<8|nfulnlMsgPacket {
				if p := c.parsePacket(m.data); p != nil {
					emit(p)
				}
			}
		}
	}
	return nil
}

func (c *nflogConn) ifname(idx uint32) string {
	if name, ok := c.ifnames[idx]; ok {
		return name
	}
	name := "if" + strconv.Itoa(int(idx))
	if ifi, err := net.InterfaceByIndex(int(idx)); err == nil {
		name = ifi.Name
	}
	c.ifnames[idx] = name
	return name
}

// parsePacket decodes an NFULNL_MSG_PACKET body (nfgenmsg + attributes).
// The data comes from the network: every length is checked.
func (c *nflogConn) parsePacket(data []byte) *nflogPacket {
	if len(data) < 4 {
		return nil
	}
	p := &nflogPacket{Group: be.Uint16(data[2:4]), Hook: -1, UID: -1, GID: -1, Time: time.Now()}
	at := parseAttrs(data[4:])
	if v := at[nfulaPacketHdr]; len(v) >= 4 {
		p.Hook = int(v[2])
	}
	if v := at[nfulaMark]; len(v) >= 4 {
		p.Mark = be.Uint32(v)
	}
	if v := at[nfulaTimestamp]; len(v) >= 16 {
		if sec, usec := be.Uint64(v[0:8]), be.Uint64(v[8:16]); sec > 0 && sec < 1<<40 && usec < 1e6 {
			p.Time = time.Unix(int64(sec), int64(usec)*1000)
		}
	}
	if v := at[nfulaIfIndev]; len(v) >= 4 {
		p.InDev = c.ifname(be.Uint32(v))
	}
	if v := at[nfulaIfOutdev]; len(v) >= 4 {
		p.OutDev = c.ifname(be.Uint32(v))
	}
	if v := at[nfulaPrefix]; len(v) > 0 {
		if i := strings.IndexByte(string(v), 0); i >= 0 {
			v = v[:i]
		}
		p.Prefix = string(v)
	}
	if v := at[nfulaUID]; len(v) >= 4 {
		p.UID = int64(be.Uint32(v))
	}
	if v := at[nfulaGID]; len(v) >= 4 {
		p.GID = int64(be.Uint32(v))
	}
	if v := at[nfulaPayload]; len(v) > 0 {
		p.Payload = append([]byte(nil), v[:min(len(v), nflogCopyRange)]...)
	}
	p.Info = decodePacket(p.Payload)
	return p
}

// decodePacket decodes IPv4/IPv6 and TCP/UDP/SCTP/ICMP headers as far as
// the (possibly truncated) data allows.
func decodePacket(b []byte) pktInfo {
	pi := pktInfo{SPort: -1, DPort: -1, ICMPType: -1, ICMPCode: -1, ID: -1}
	if len(b) == 0 {
		return pi
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return pi
		}
		ihl := int(b[0]&0x0f) * 4
		pi.Version = 4
		pi.TotalLen = int(be.Uint16(b[2:4]))
		pi.ID = int(be.Uint16(b[4:6]))
		frag := be.Uint16(b[6:8])
		pi.Frag = frag&0x3fff != 0 // MF set or offset != 0
		pi.TTL = int(b[8])
		pi.Proto = b[9]
		pi.Src, pi.Dst = net.IP(append([]byte(nil), b[12:16]...)), net.IP(append([]byte(nil), b[16:20]...))
		if frag&0x1fff == 0 && ihl >= 20 && ihl <= len(b) {
			decodeL4(&pi, b[ihl:])
		}
	case 6:
		if len(b) < 40 {
			return pi
		}
		pi.Version = 6
		pi.TotalLen = 40 + int(be.Uint16(b[4:6]))
		pi.TTL = int(b[7])
		pi.Src, pi.Dst = net.IP(append([]byte(nil), b[8:24]...)), net.IP(append([]byte(nil), b[24:40]...))
		next, off, l4 := b[6], 40, true
	walk:
		for i := 0; i < 8; i++ {
			switch next {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if off+2 > len(b) {
					l4 = false
					break walk
				}
				next, off = b[off], off+(int(b[off+1])+1)*8
			case 44: // fragment
				if off+8 > len(b) {
					l4 = false
					break walk
				}
				pi.Frag = true
				if be.Uint16(b[off+2:off+4])>>3 != 0 {
					l4 = false // not the first fragment: no transport header
				}
				next, off = b[off], off+8
			case 51: // AH
				if off+2 > len(b) {
					l4 = false
					break walk
				}
				next, off = b[off], off+(int(b[off+1])+2)*4
			default:
				break walk
			}
		}
		pi.Proto = next
		if l4 && off <= len(b) {
			decodeL4(&pi, b[off:])
		}
	}
	return pi
}

func decodeL4(pi *pktInfo, b []byte) {
	switch pi.Proto {
	case 6, 17, 132, 136: // TCP, UDP, SCTP, UDP-Lite
		if len(b) >= 4 {
			pi.SPort, pi.DPort = int(be.Uint16(b[0:2])), int(be.Uint16(b[2:4]))
		}
		if pi.Proto == 6 && len(b) >= 14 {
			var flags []string
			for i, name := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
				if b[13]&(1<<i) != 0 {
					flags = append(flags, name)
				}
			}
			pi.TCPFlags = strings.Join(flags, ",")
		}
	case 1, 58: // ICMP, ICMPv6
		if len(b) >= 2 {
			pi.ICMPType, pi.ICMPCode = int(b[0]), int(b[1])
		}
	}
}

var protoNames = map[uint8]string{1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP",
	51: "AH", 58: "ICMPv6", 89: "OSPF", 112: "VRRP", 132: "SCTP", 136: "UDPLite"}

func (pi pktInfo) protoName() string {
	if pi.Version == 0 {
		return "?"
	}
	if n, ok := protoNames[pi.Proto]; ok {
		return n
	}
	return strconv.Itoa(int(pi.Proto))
}

func hostPort(ip net.IP, port int) string {
	if port < 0 {
		return ip.String()
	}
	if ip.To4() == nil {
		return "[" + ip.String() + "]:" + strconv.Itoa(port)
	}
	return ip.String() + ":" + strconv.Itoa(port)
}

func ifaces(in, out string) string {
	if in == "" && out == "" {
		return "-"
	}
	return in + ">" + out
}

// summary is the one-line form shown in the packet list.
func (p *nflogPacket) summary() string {
	pi := p.Info
	var b strings.Builder
	fmt.Fprintf(&b, "%-12s %-6s ", fit(ifaces(p.InDev, p.OutDev), 12), pi.protoName())
	if pi.Version == 0 {
		fmt.Fprintf(&b, "(%d bytes, not IP)", len(p.Payload))
	} else {
		b.WriteString(hostPort(pi.Src, pi.SPort) + " -> " + hostPort(pi.Dst, pi.DPort))
		switch {
		case pi.TCPFlags != "":
			b.WriteString(" " + pi.TCPFlags)
		case pi.ICMPType >= 0:
			fmt.Fprintf(&b, " type %d/%d", pi.ICMPType, pi.ICMPCode)
		}
		if pi.Frag {
			b.WriteString(" frag")
		}
		fmt.Fprintf(&b, " len %d", pi.TotalLen)
	}
	if p.Prefix != "" {
		b.WriteString("  " + quoteArg(p.Prefix))
	}
	return b.String()
}

func hexDump(b []byte, max int) []string {
	var lines []string
	for off := 0; off < len(b) && off < max; off += 16 {
		end := min(off+16, len(b))
		var hx, asc strings.Builder
		for i := off; i < off+16; i++ {
			if i < end {
				fmt.Fprintf(&hx, "%02x ", b[i])
				if c := b[i]; c >= 0x20 && c < 0x7f {
					asc.WriteByte(c)
				} else {
					asc.WriteByte('.')
				}
			} else {
				hx.WriteString("   ")
			}
		}
		lines = append(lines, fmt.Sprintf("%04x  %s %s", off, hx.String(), asc.String()))
	}
	return lines
}
