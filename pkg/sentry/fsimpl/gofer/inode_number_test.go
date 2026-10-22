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

// unmix63 is the inverse of mix63.
func unmix63(x uint64) uint64 {
	x ^= x >> 32
	x = (x * 0x319642b2d24d8ec3) & inoMask // Inverse of 0x94d049bb133111eb mod 2^63.
	x ^= x >> 32
	x = (x * 0x16de1b173f119089) & inoMask // Inverse of 0xbf58476d1ce4e5b9 mod 2^63.
	x ^= x >> 32
	return x
}

// unino returns the remote inode key, on the given device and below 2^63,
// that m maps to ino.
func (m *inoMapper) unino(devMajor, devMinor uint32, ino uint64) inoKey {
	dev := uint64(devMajor)<<32 | uint64(devMinor)
	tweak := mix64(mix64(dev ^ m.k2))
	return inoKey{
		ino:      (unmix63(unmix63(ino)^m.k1&inoMask) ^ m.k0 ^ tweak) & inoMask,
		devMajor: devMajor,
		devMinor: devMinor,
	}
}

func TestMix63IsBijection(t *testing.T) {
	for _, x := range []uint64{0, 1, 2, 0xffffffff, 1 << 62, inoMask, 0x0123456789abcdef} {
		y := mix63(x)
		if y > inoMask {
			t.Errorf("mix63(%#x) = %#x, want < 2^63", x, y)
		}
		if got := unmix63(y); got != x {
			t.Errorf("unmix63(mix63(%#x)) = %#x", x, got)
		}
	}
}

func TestInoMapper(t *testing.T) {
	m := newInoMapper()
	seen := make(map[uint64]inoKey)
	for dev := uint32(0); dev < 4; dev++ {
		for ino := uint64(1); ino <= 1<<16; ino++ {
			key := inoKey{ino: ino, devMajor: dev, devMinor: 7}
			got := m.ino(key)
			if got != m.ino(key) {
				t.Fatalf("ino(%+v) is not stable", key)
			}
			if prev, ok := seen[got]; ok {
				t.Fatalf("ino(%+v) = ino(%+v) = %#x", key, prev, got)
			}
			if got > inoMask {
				t.Fatalf("ino(%+v) = %#x, want < 2^63", key, got)
			}
			seen[got] = key
			if back := m.unino(key.devMajor, key.devMinor, got); back != key {
				t.Fatalf("unino(ino(%+v)) = %+v", key, back)
			}
		}
	}

	// Remote inode numbers at or above 2^63 must not collide with the same
	// inode number below 2^63.
	for ino := uint64(1); ino <= 1<<16; ino++ {
		key := inoKey{ino: ino | 1<<63, devMajor: 0, devMinor: 7}
		got := m.ino(key)
		if got > inoMask {
			t.Fatalf("ino(%+v) = %#x, want < 2^63", key, got)
		}
		if prev, ok := seen[got]; ok {
			t.Fatalf("ino(%+v) = ino(%+v) = %#x", key, prev, got)
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
		remappedInos: make(map[uint64]struct{}),
	}
}

func TestInoFromKey(t *testing.T) {
	fs := newInoTestFilesystem()
	key := inoKey{ino: 12345, devMajor: 0, devMinor: 42}
	if got, want := fs.inoFromKey(key), fs.inoMapper.ino(key); got != want {
		t.Errorf("inoFromKey(%+v) = %#x, want %#x", key, got, want)
	}
	if len(fs.inoByKey) != 0 || fs.hasRemappedInos.Load() {
		t.Errorf("inoFromKey stored state for %+v: inoByKey = %v", key, fs.inoByKey)
	}
}

func TestInoFromKeyZero(t *testing.T) {
	fs := newInoTestFilesystem()
	fs.lastIno.Store(100)
	key := fs.inoMapper.unino(0, 42, 0)
	if fs.inoMapper.ino(key) != 0 {
		t.Fatalf("test key %+v does not map to 0", key)
	}
	got := fs.inoFromKey(key)
	if got == 0 {
		t.Fatalf("inoFromKey(%+v) = 0", key)
	}
	if again := fs.inoFromKey(key); again != got {
		t.Errorf("inoFromKey(%+v) changed from %#x to %#x", key, got, again)
	}
}

// TestInoFromKeyRestored simulates restoring a file whose remote inode key
// changed, and a new file that now has the restored file's old remote key.
func TestInoFromKeyRestored(t *testing.T) {
	fs := newInoTestFilesystem()
	fs.lastIno.Store(100)
	oldKey := inoKey{ino: 1000, devMajor: 0, devMinor: 42}
	newKey := inoKey{ino: 2000, devMajor: 0, devMinor: 42}
	restoredIno := fs.inoFromKey(oldKey)

	// Restore with a new mapper key, as CompleteRestore does.
	fs.inoMapper = newInoMapper()
	fs.inoMu.Lock()
	fs.setInoLocked(newKey, restoredIno)
	fs.inoMu.Unlock()

	if got := fs.inoFromKey(newKey); got != restoredIno {
		t.Errorf("inoFromKey(restored file) = %#x, want %#x", got, restoredIno)
	}
	other := inoKey{ino: 3000, devMajor: 0, devMinor: 42}
	if got, want := fs.inoFromKey(other), fs.inoMapper.ino(other); got != want {
		t.Errorf("inoFromKey(%+v) = %#x, want %#x", other, got, want)
	}

	// A file that the new mapper happens to map to the restored inode number
	// must get a different inode number.
	clash := fs.inoMapper.unino(0, 42, restoredIno)
	got := fs.inoFromKey(clash)
	if got == restoredIno || got == 0 {
		t.Errorf("inoFromKey(%+v) = %#x, which is the restored file's inode number or 0", clash, got)
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
