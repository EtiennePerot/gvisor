// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gvisorbinaries

import (
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openFD(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open(%q): %v", path, err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// TestLoadedRangesMatchesDebugELF checks loadedRanges against debug/elf on the
// test binary.
func TestLoadedRangesMatchesDebugELF(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	f, err := elf.Open(exe)
	if err != nil {
		t.Fatalf("elf.Open(%q): %v", exe, err)
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		t.Skipf("%q is not a 64-bit little-endian ELF file", exe)
	}
	var want [][2]int64
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Filesz > 0 {
			want = append(want, [2]int64{int64(p.Off), int64(p.Off + p.Filesz)})
		}
	}
	if len(want) == 0 {
		t.Fatalf("no PT_LOAD segments in %q", exe)
	}
	st, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got := loadedRanges(openFD(t, exe), st.Size()); !slices.Equal(got, want) {
		t.Errorf("loadedRanges(%q) = %v, want %v", exe, got, want)
	}
}

// makeELF returns a 64-bit little-endian ELF header followed by program
// headers with the given types, offsets and file sizes.
func makeELF(phdrs ...[3]uint64) []byte {
	b := make([]byte, elfHeaderSize+len(phdrs)*elfPhdrSize)
	copy(b, "\x7fELF\x02\x01")
	binary.LittleEndian.PutUint64(b[elfPhoffOffset:], elfHeaderSize)
	binary.LittleEndian.PutUint16(b[elfPhentsizeOffs:], elfPhdrSize)
	binary.LittleEndian.PutUint16(b[elfPhnumOffset:], uint16(len(phdrs)))
	for i, ph := range phdrs {
		p := b[elfHeaderSize+i*elfPhdrSize:]
		binary.LittleEndian.PutUint32(p, uint32(ph[0]))
		binary.LittleEndian.PutUint64(p[8:], ph[1])
		binary.LittleEndian.PutUint64(p[32:], ph[2])
	}
	return b
}

func TestLoadedRangesSynthetic(t *testing.T) {
	const ptNote = 4
	for _, tc := range []struct {
		name  string
		phdrs [][3]uint64
		size  int64
		want  [][2]int64
	}{
		{"two loads", [][3]uint64{{elfPTLoad, 0, 100}, {ptNote, 100, 10}, {elfPTLoad, 4096, 50}}, 8192, [][2]int64{{0, 100}, {4096, 4146}}},
		{"empty load", [][3]uint64{{elfPTLoad, 0, 0}, {elfPTLoad, 4096, 50}}, 8192, [][2]int64{{4096, 4146}}},
		{"no load", [][3]uint64{{ptNote, 0, 10}}, 8192, nil},
		{"load ends at size", [][3]uint64{{elfPTLoad, 4096, 4096}}, 8192, [][2]int64{{4096, 8192}}},
		{"load past size", [][3]uint64{{elfPTLoad, 4096, 4097}}, 8192, nil},
		{"load overflows", [][3]uint64{{elfPTLoad, 4096, ^uint64(0)}}, 8192, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := makeELF(tc.phdrs...)
			data = append(data, make([]byte, tc.size-int64(len(data)))...)
			p := filepath.Join(t.TempDir(), "f")
			if err := os.WriteFile(p, data, 0644); err != nil {
				t.Fatal(err)
			}
			if got := loadedRanges(openFD(t, p), tc.size); !slices.Equal(got, tc.want) {
				t.Errorf("loadedRanges = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoadedRangesNotELF(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", []byte("\x7fELF")},
		{"zeroes", make([]byte, 128)},
		{"elf32", append([]byte("\x7fELF\x01\x01"), make([]byte, 122)...)},
		{"no phdrs", append([]byte("\x7fELF\x02\x01"), make([]byte, 122)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "f")
			if err := os.WriteFile(p, tc.data, 0644); err != nil {
				t.Fatal(err)
			}
			if got := loadedRanges(openFD(t, p), int64(len(tc.data))); got != nil {
				t.Errorf("loadedRanges = %v, want nil", got)
			}
		})
	}
}

func TestSampleOffsets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ranges [][2]int64
		n      int
		want   []int64
	}{
		{"one range", [][2]int64{{100, 200}}, 3, []int64{100, 149, 199}},
		{"one sample", [][2]int64{{100, 200}}, 1, []int64{100}},
		{"two ranges", [][2]int64{{0, 10}, {1000, 1010}}, 4, []int64{0, 6, 1002, 1009}},
		{"tiny ranges", [][2]int64{{0, 1}, {5, 6}, {9, 10}}, 3, []int64{0, 5, 9}},
		{"more samples than bytes", [][2]int64{{7, 9}}, 4, []int64{7, 7, 7, 8}},
		{"empty", nil, 4, []int64{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var total int64
			for _, r := range tc.ranges {
				total += r[1] - r[0]
			}
			if got := sampleOffsets(tc.ranges, total, tc.n); !slices.Equal(got, tc.want) {
				t.Errorf("sampleOffsets(%v, %d, %d) = %v, want %v", tc.ranges, total, tc.n, got, tc.want)
			}
		})
	}
}

// evict writes back and drops the page cache of the file at path. It skips the
// test if the file's filesystem doesn't support it or RWF_NOWAIT.
func evict(t *testing.T, path string, ranges [][2]int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED); err != nil {
		t.Skipf("fadvise(DONTNEED): %v", err)
	}
	if !isCold(int(f.Fd()), ranges) {
		t.Skipf("cannot evict %q from the page cache, or its filesystem doesn't support RWF_NOWAIT", path)
	}
}

// TestPrefetch checks that Prefetch brings the loaded segments of an evicted
// copy of the test binary into the page cache.
func TestPrefetch(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// Copy the binary outside of TEST_TMPDIR, which may be on tmpfs.
	dir, err := os.MkdirTemp(filepath.Dir(exe), "prefetch")
	if err != nil {
		dir = t.TempDir()
	} else {
		t.Cleanup(func() { os.RemoveAll(dir) })
	}
	p := filepath.Join(dir, "exe")
	copyFile(t, exe, p)
	fd := openFD(t, p)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	ranges := loadedRanges(fd, st.Size)
	if ranges == nil {
		t.Fatalf("loadedRanges(%q) = nil", p)
	}
	evict(t, p, ranges)

	Prefetch(p)
	for deadline := time.Now().Add(10 * time.Second); isCold(fd, ranges); {
		if time.Now().After(deadline) {
			t.Fatalf("%q not cached 10s after Prefetch", p)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestNotColdAfterWrite checks that isCold reports a just-written file as not
// cold, so that Prefetch does nothing for it.
func TestNotColdAfterWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	size := int64(64*os.Getpagesize() + 123)
	if err := os.WriteFile(p, make([]byte, size), 0644); err != nil {
		t.Fatal(err)
	}
	if isCold(openFD(t, p), [][2]int64{{0, size}}) {
		t.Errorf("isCold(%q) = true, want false", p)
	}
}

// TestPrefetchIgnoresErrors checks that Prefetch tolerates missing, empty,
// non-ELF and non-regular files.
func TestPrefetchIgnoresErrors(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	text := filepath.Join(dir, "text")
	if err := os.WriteFile(empty, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(text, make([]byte, 3*os.Getpagesize()+5), 0644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "missing"), empty, text, dir, "/dev/null"} {
		Prefetch(p)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
}
