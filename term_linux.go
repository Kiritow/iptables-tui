package main

import (
	"os"
	"syscall"
	"unsafe"
)

// termState holds the terminal attributes to restore on exit.
type termState struct {
	fd  int
	old syscall.Termios
}

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}

// makeRaw puts the terminal into raw mode (like cfmakeraw) and returns the previous state.
func makeRaw(fd int) (*termState, error) {
	var t syscall.Termios
	if err := ioctl(fd, syscall.TCGETS, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	st := &termState{fd: fd, old: t}
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	if err := ioctl(fd, syscall.TCSETS, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *termState) restore() {
	_ = ioctl(s.fd, syscall.TCSETS, unsafe.Pointer(&s.old))
}

type winsize struct {
	Row, Col, Xpixel, Ypixel uint16
}

func termSize(fd int) (w, h int, err error) {
	var ws winsize
	if err := ioctl(fd, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0, 0, err
	}
	return int(ws.Col), int(ws.Row), nil
}

// readInput forwards raw stdin chunks to ch until stdin is closed.
func readInput(f *os.File, ch chan<- []byte) {
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			b := make([]byte, n)
			copy(b, buf[:n])
			ch <- b
		}
		if err != nil {
			close(ch)
			return
		}
	}
}
