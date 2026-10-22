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

package gofer

import (
	"testing"
)

// unmix52 is the inverse of mix52.
func unmix52(x uint64) uint64 {
	x ^= x >> 26
	x = (x * 0x642b2d24d8ec3) & inoMappedMask // Inverse of 0x94d049bb133111eb mod 2^52.
	x ^= x >> 26
	x = (x * 0xe1b173f119089) & inoMappedMask // Inverse of 0xbf58476d1ce4e5b9 mod 2^52.
	x ^= x >> 26
	return x
}

// unino returns the remote inode key, on the given device, that m maps to ino.
func (m *inoMapper) unino(devMajor, devMinor uint32, ino uint64) inoKey {
	dev := uint64(devMajor)<<32 | uint64(devMinor)
	tweak := mix64(dev ^ m.k2)
	return inoKey{
		ino:      (unmix52(unmix52(ino&inoMappedMask)^m.k1&inoMappedMask) ^ m.k0 ^ tweak) & inoMappedMask,
		devMajor: devMajor,
		devMinor: devMinor,
	}
}

func TestMix52IsBijection(t *testing.T) {
	for _, x := range []uint64{0, 1, 2, 0xffffffff, 1 << 51, inoMappedMask, 0x0123456789abc} {
		y := mix52(x)
		if y > inoMappedMask {
			t.Errorf("mix52(%#x) = %#x, want < 2^52", x, y)
		}
		if got := unmix52(y); got != x {
			t.Errorf("unmix52(mix52(%#x)) = %#x", x, got)
		}
	}
}

func TestInoMapper(t *testing.T) {
	m := newInoMapper()
	seen := make(map[uint64]inoKey)
	for dev := uint32(0); dev < 4; dev++ {
		for _, base := range []uint64{0, inoMappedMask - 1<<14} {
			for ino := base + 1; ino <= base+1<<14; ino++ {
				key := inoKey{ino: ino, devMajor: dev, devMinor: 7}
				got := m.ino(key)
				if got != m.ino(key) {
					t.Fatalf("ino(%+v) is not stable", key)
				}
				if got < inoMappedBit || got >= 2*inoMappedBit {
					t.Fatalf("ino(%+v) = %#x, want in [2^52, 2^53)", key, got)
				}
				if prev, ok := seen[got]; ok {
					t.Fatalf("ino(%+v) = ino(%+v) = %#x", key, prev, got)
				}
				seen[got] = key
				if back := m.unino(key.devMajor, key.devMinor, got); back != key {
					t.Fatalf("unino(ino(%+v)) = %+v", key, back)
				}
			}
		}
	}

	// Different keys should map the same file to different inode numbers.
	m2 := newInoMapper()
	key := inoKey{ino: 2, devMajor: 8, devMinor: 1}
	if m.ino(key) == m2.ino(key) {
		t.Errorf("two inoMappers both map %+v to %#x", key, m.ino(key))
	}
}

func newInoTestFilesystem() *filesystem {
	return &filesystem{
		inoMapper:    newInoMapper(),
		inoByKey:     make(map[inoKey]uint64),
		reservedInos: make(map[uint64]struct{}),
	}
}

func TestInoFromKey(t *testing.T) {
	fs := newInoTestFilesystem()
	key := inoKey{ino: 12345, devMajor: 0, devMinor: 42}
	if got, want := fs.inoFromKey(key), fs.inoMapper.ino(key); got != want {
		t.Errorf("inoFromKey(%+v) = %#x, want %#x", key, got, want)
	}
	if len(fs.inoByKey) != 0 {
		t.Errorf("inoFromKey stored state for %+v: inoByKey = %v", key, fs.inoByKey)
	}
}

// TestInoFromKeyLarge checks that remote inode numbers that cannot be mapped
// receive stable allocated inode numbers, disjoint from mapped ones.
func TestInoFromKeyLarge(t *testing.T) {
	fs := newInoTestFilesystem()
	synthetic := fs.nextIno()
	var inos []uint64
	for _, rino := range []uint64{inoMappedBit, 1<<62 | 5, ^uint64(0)} {
		key := inoKey{ino: rino, devMajor: 0, devMinor: 42}
		got := fs.inoFromKey(key)
		if got == 0 || got >= inoMappedBit {
			t.Errorf("inoFromKey(%+v) = %#x, want in (0, 2^52)", key, got)
		}
		if got == synthetic {
			t.Errorf("inoFromKey(%+v) = %#x, which was already allocated", key, got)
		}
		if again := fs.inoFromKey(key); again != got {
			t.Errorf("inoFromKey(%+v) changed from %#x to %#x", key, got, again)
		}
		inos = append(inos, got)
	}
	if inos[0] == inos[1] || inos[1] == inos[2] || inos[0] == inos[2] {
		t.Errorf("duplicate inode numbers: %v", inos)
	}
	// Mapped inode numbers are still computed without state.
	if fs.hasRestoredInos.Load() {
		t.Errorf("large remote inode numbers disabled the fast path")
	}
}

func TestNextInoBelowMappedRange(t *testing.T) {
	fs := newInoTestFilesystem()
	fs.lastIno.Store(inoMappedMask - 1)
	if got := fs.nextIno(); got != inoMappedMask {
		t.Errorf("nextIno() = %#x, want %#x", got, uint64(inoMappedMask))
	}
	defer func() {
		if recover() == nil {
			t.Errorf("nextIno() did not panic after exhausting [1, 2^52)")
		}
	}()
	fs.nextIno()
}

// TestInoFromKeyRestored simulates restoring a file whose remote inode key
// changed, and a new file that now maps to the restored file's inode number.
func TestInoFromKeyRestored(t *testing.T) {
	fs := newInoTestFilesystem()
	oldKey := inoKey{ino: 1000, devMajor: 0, devMinor: 42}
	newKey := inoKey{ino: 2000, devMajor: 0, devMinor: 42}
	restoredIno := fs.inoFromKey(oldKey)
	largeKey := inoKey{ino: 1 << 60, devMajor: 0, devMinor: 42}
	restoredLargeIno := fs.inoFromKey(largeKey)

	// Restore with a new mapper key, as CompleteRestore does.
	fs.inoMapper = newInoMapper()
	fs.inoByKey = make(map[inoKey]uint64)
	fs.reservedInos = make(map[uint64]struct{})
	fs.inoMu.Lock()
	fs.setRestoredInoLocked(newKey, restoredIno)
	fs.setRestoredInoLocked(largeKey, restoredLargeIno)
	fs.inoMu.Unlock()

	if got := fs.inoFromKey(newKey); got != restoredIno {
		t.Errorf("inoFromKey(restored file) = %#x, want %#x", got, restoredIno)
	}
	if got := fs.inoFromKey(largeKey); got != restoredLargeIno {
		t.Errorf("inoFromKey(restored large file) = %#x, want %#x", got, restoredLargeIno)
	}
	other := inoKey{ino: 3000, devMajor: 0, devMinor: 42}
	if got, want := fs.inoFromKey(other), fs.inoMapper.ino(other); got != want {
		t.Errorf("inoFromKey(%+v) = %#x, want %#x", other, got, want)
	}

	// A file that the new mapper happens to map to the restored inode number
	// must get a different inode number.
	clash := fs.inoMapper.unino(0, 42, restoredIno)
	if fs.inoMapper.ino(clash) != restoredIno {
		t.Fatalf("test key %+v does not map to %#x", clash, restoredIno)
	}
	got := fs.inoFromKey(clash)
	if got == restoredIno || got == restoredLargeIno || got == 0 {
		t.Errorf("inoFromKey(%+v) = %#x, which is a restored file's inode number or 0", clash, got)
	}
	if again := fs.inoFromKey(clash); again != got {
		t.Errorf("inoFromKey(%+v) changed from %#x to %#x", clash, got, again)
	}
}

func BenchmarkInoFromKey(b *testing.B) {
	fs := newInoTestFilesystem()
	key := inoKey{devMajor: 0, devMinor: 42}
	for i := 0; i < b.N; i++ {
		key.ino = uint64(i)
		fs.inoFromKey(key)
	}
}
