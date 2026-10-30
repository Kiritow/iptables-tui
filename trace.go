package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// traceStep is one evaluation step of a traced packet.
type traceStep struct {
	Table, Chain string
	Type         string // rule, return, policy; "packet" marks a changed packet (e.g. after NAT)
	Verdict      string // nft: CONTINUE, ACCEPT, DROP, JUMP:X, RETURN, ...
	Rule         string // nft: the rule as an iptables command; "packet": the new packet fields
	RuleNum      int    // legacy: rule position in the chain
}

// traceItem is the path of one packet through the ruleset.
type traceItem struct {
	ID         string
	Family     Family // 0 if unknown
	Packet     string // packet fields as printed by the kernel / xtables-monitor
	lastPacket string
	Steps      []traceStep
}

// parseXtmLine parses an `xtables-monitor --trace` line:
//
//	PACKET: 2 6bf9b106 OUT=lo SRC=127.0.0.1 ...
//	 TRACE: 2 6bf9b106 filter:OUTPUT:rule:0x5:JUMP:CHK  iptables -t filter -A OUTPUT -p tcp -j CHK
func parseXtmLine(line string) (kind string, fam Family, id, rest string, ok bool) {
	line = strings.TrimLeft(line, " ")
	kind, line, ok = strings.Cut(line, ": ")
	if !ok || (kind != "PACKET" && kind != "TRACE") {
		return "", 0, "", "", false
	}
	f := strings.SplitN(line, " ", 3)
	if len(f) < 2 {
		return "", 0, "", "", false
	}
	switch f[0] {
	case "2":
		fam = V4
	case "10":
		fam = V6
	}
	if len(f) == 3 {
		rest = strings.TrimRight(f[2], " ")
	}
	return kind, fam, f[1], rest, true
}

var nftVerdicts = map[string]string{"0xffffffff": "CONTINUE", "0xfffffffe": "BREAK", "0xfffffffd": "JUMP",
	"0xfffffffc": "GOTO", "0xfffffffb": "RETURN"}

// parseXtmStep parses "table:chain:type[:handle]:verdict[:target]  rule text".
func parseXtmStep(s string) traceStep {
	spec, rule, _ := strings.Cut(s, "  ")
	p := strings.Split(strings.TrimSpace(spec), ":")
	st := traceStep{Rule: strings.TrimSpace(rule)}
	if len(p) >= 3 {
		st.Table, st.Chain, st.Type = p[0], p[1], p[2]
	}
	switch {
	case st.Type == "rule" && len(p) >= 5:
		st.Verdict = strings.Join(p[4:], ":")
	case len(p) >= 4:
		st.Verdict = strings.Join(p[3:], ":")
	}
	if v, ok := nftVerdicts[st.Verdict]; ok {
		st.Verdict = v
	}
	return st
}

// parseKmsgTrace parses a legacy TRACE kernel log message:
//
//	TRACE: raw:PREROUTING:rule:2 IN=eth0 OUT= MAC=... SRC=10.0.0.1 DST=10.0.0.2 ...
func parseKmsgTrace(msg string) (traceStep, string, bool) {
	rest, ok := strings.CutPrefix(msg, "TRACE: ")
	if !ok {
		return traceStep{}, "", false
	}
	spec, pkt, _ := strings.Cut(rest, " ")
	p := strings.Split(spec, ":")
	if len(p) != 4 {
		return traceStep{}, "", false
	}
	n, _ := strconv.Atoi(p[3])
	return traceStep{Table: p[0], Chain: p[1], Type: p[2], RuleNum: n}, strings.TrimSpace(pkt), true
}

// packetFields splits "KEY=value" fields and bare flags (DF, SYN, ...).
func packetFields(s string) (map[string]string, []string) {
	kv := map[string]string{}
	var flags []string
	for _, f := range strings.Fields(s) {
		if k, v, ok := strings.Cut(f, "="); ok {
			if _, dup := kv[k]; !dup {
				kv[k] = v
			}
		} else {
			flags = append(flags, f)
		}
	}
	return kv, flags
}

// packetKey identifies a packet across legacy TRACE lines (the interfaces
// change between hooks, the rest does not).
func packetKey(pkt string) string {
	var keep []string
	for _, f := range strings.Fields(pkt) {
		switch k, _, _ := strings.Cut(f, "="); k {
		case "IN", "OUT", "MAC", "PHYSIN", "PHYSOUT":
		default:
			keep = append(keep, f)
		}
	}
	return strings.Join(keep, " ")
}

func (t *traceItem) verdict() (string, Style) {
	for i := len(t.Steps) - 1; i >= 0; i-- {
		s := t.Steps[i]
		where := s.Table + ":" + s.Chain
		switch {
		case s.Type == "packet":
			continue
		case s.Verdict == "ACCEPT":
			return where + " ACCEPT", fg(cGreen)
		case s.Verdict == "DROP":
			return where + " DROP", fg(cRed).with(AttrBold)
		case s.Verdict != "" && s.Verdict != "CONTINUE" && s.Verdict != "RETURN" && !strings.HasPrefix(s.Verdict, "JUMP"):
			return where + " " + s.Verdict, fg(cYellow)
		case s.Type == "policy" && s.Verdict == "":
			return where + " policy", stDefault // legacy: policy verdict not printed
		}
	}
	return "…", stDim
}

func (t *traceItem) summary() (string, Style) {
	kv, flags := packetFields(t.Packet)
	src, dst := kv["SRC"], kv["DST"]
	if p := kv["SPORT"] + kv["SPT"]; p != "" {
		src = joinHostPort(src, p)
	}
	if p := kv["DPORT"] + kv["DPT"]; p != "" {
		dst = joinHostPort(dst, p)
	}
	var tcp []string
	for _, f := range flags {
		if contains([]string{"SYN", "ACK", "FIN", "RST", "PSH", "URG"}, f) {
			tcp = append(tcp, f)
		}
	}
	proto := kv["PROTO"]
	if proto == "" {
		proto = "-"
	}
	v, st := t.verdict()
	s := fmt.Sprintf("%-12s %-6s %s -> %s", fit(ifaces(kv["IN"], kv["OUT"]), 12), proto, src, dst)
	if len(tcp) > 0 {
		s += " " + strings.Join(tcp, ",")
	}
	return fmt.Sprintf("%s  => %s  (%d steps)", s, v, len(t.Steps)), st
}

func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// ---- trace sources ----

// startXtablesMonitor runs `xtables-monitor --trace` (nft backend) and feeds
// its lines to onLine until stop is called or it exits.
func startXtablesMonitor(bin string, onLine func(string), onExit func(error)) (stop func(), err error) {
	cmd := exec.Command(bin, "--trace")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var stopped atomic.Bool
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			onLine(sc.Text())
		}
		err := cmd.Wait()
		if stopped.Load() {
			err = nil
		} else if msg := cleanErr(stderr.String()); msg != "" {
			err = errors.New(msg)
		}
		onExit(err)
	}()
	return func() {
		stopped.Store(true)
		_ = cmd.Process.Kill()
	}, nil
}

// startKmsgTrace follows the kernel log for TRACE messages, which is where
// the legacy backend writes them.
func startKmsgTrace(onLine func(string), onExit func(error)) (stop func(), err error) {
	fd, err := syscall.Open("/dev/kmsg", syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("/dev/kmsg: %w", err)
	}
	if _, err := syscall.Seek(fd, 0, io.SeekEnd); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("/dev/kmsg: %w", err)
	}
	f := os.NewFile(uintptr(fd), "/dev/kmsg") // non-blocking: Close interrupts Read
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := f.Read(buf)
			if errors.Is(err, syscall.EPIPE) {
				continue // records were overwritten before we read them
			}
			if err != nil {
				if errors.Is(err, os.ErrClosed) {
					err = nil
				}
				onExit(err)
				return
			}
			// "prio,seq,usec,flags;message\n continuation lines"
			rec := string(buf[:n])
			if _, msg, ok := strings.Cut(rec, ";"); ok {
				msg, _, _ = strings.Cut(msg, "\n")
				if strings.HasPrefix(msg, "TRACE: ") {
					onLine(msg)
				}
			}
		}
	}()
	return func() { f.Close() }, nil
}

func findXtablesMonitor(iptablesBin string) (string, error) {
	if p, err := findBinary(filepath.Join(filepath.Dir(iptablesBin), "xtables-monitor")); err == nil {
		return p, nil
	}
	return findBinary("xtables-monitor")
}

// ---- pcap export ----

// writePcap writes IP packets as a pcap file with LINKTYPE_RAW, readable by
// Wireshark and tcpdump. Truncated packets keep their original length.
func writePcap(path string, pkts []*nflogPacket) (int, error) {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	le := binary.LittleEndian
	le.PutUint32(hdr[0:], 0xa1b2c3d4)
	le.PutUint16(hdr[4:], 2)
	le.PutUint16(hdr[6:], 4)
	le.PutUint32(hdr[16:], 65535)
	le.PutUint32(hdr[20:], 101) // LINKTYPE_RAW
	b.Write(hdr)
	n := 0
	for _, p := range pkts {
		if p.Info.Version == 0 {
			continue
		}
		rec := make([]byte, 16)
		le.PutUint32(rec[0:], uint32(p.Time.Unix()))
		le.PutUint32(rec[4:], uint32(p.Time.Nanosecond()/1000))
		le.PutUint32(rec[8:], uint32(len(p.Payload)))
		le.PutUint32(rec[12:], uint32(max(len(p.Payload), p.Info.TotalLen)))
		b.Write(rec)
		b.Write(p.Payload)
		n++
	}
	return n, writeFileAtomic(path, b.Bytes(), 0o640)
}

var traceTimeout = 10 * time.Second
