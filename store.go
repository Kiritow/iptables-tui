package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// DisabledEntry is the original rule behind a disabled placeholder.
type DisabledEntry struct {
	ID         string    `json:"id"`
	Family     Family    `json:"family"`
	Table      string    `json:"table"`
	Chain      string    `json:"chain"`
	Args       []string  `json:"args"`
	Pkts       uint64    `json:"pkts"`
	Bytes      uint64    `json:"bytes"`
	DisabledAt time.Time `json:"disabled_at"`
}

type storeFile struct {
	Version int              `json:"version"`
	Rules   []*DisabledEntry `json:"rules"`
}

// Store keeps disabled rules in a JSON file. Writes take an flock on a side
// file and replace the JSON atomically, so readers never need a lock.
type Store struct {
	Path string
	mu   sync.Mutex
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (s *Store) read() (*storeFile, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return &storeFile{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Path, err)
	}
	return &f, nil
}

func (s *Store) Entries(fam Family) (map[string]*DisabledEntry, error) {
	m := map[string]*DisabledEntry{}
	f, err := s.read()
	if err != nil {
		return m, err
	}
	for _, e := range f.Rules {
		if e.Family == fam {
			m[e.ID] = e
		}
	}
	return m, nil
}

func (s *Store) update(fn func(f *storeFile)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	lf, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	f, err := s.read()
	if err != nil {
		return err
	}
	fn(f)
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.Path, append(data, '\n'), 0o600)
}

func (s *Store) Add(es ...*DisabledEntry) error {
	return s.update(func(f *storeFile) { f.Rules = append(f.Rules, es...) })
}

// Put replaces the entry with the same ID.
func (s *Store) Put(e *DisabledEntry) error {
	return s.update(func(f *storeFile) {
		for i, x := range f.Rules {
			if x.ID == e.ID {
				f.Rules[i] = e
				return
			}
		}
		f.Rules = append(f.Rules, e)
	})
}

func (s *Store) Remove(ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	return s.update(func(f *storeFile) {
		kept := f.Rules[:0]
		for _, e := range f.Rules {
			if !drop[e.ID] {
				kept = append(kept, e)
			}
		}
		f.Rules = kept
	})
}

func (s *Store) RenameChain(fam Family, table, from, to string) error {
	return s.update(func(f *storeFile) {
		for _, e := range f.Rules {
			if e.Family == fam && e.Table == table && e.Chain == from {
				e.Chain = to
			}
		}
	})
}

// writeFileAtomic replaces path (following symlinks) via a temp file and
// rename, keeping the existing file mode if there is one.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		path = p
	}
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".iptables-tui-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
