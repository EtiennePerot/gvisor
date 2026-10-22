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
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/rand"
)

// inoMapper derives sentry inode numbers from remote inode keys without
// storing per-file state.
//
// Inode numbers are kept below 2^63, since some applications store inode
// numbers in signed 64-bit integers.
//
// For a given remote device, the mapping from remote inode numbers below 2^63
// to sentry inode numbers is a bijection, so distinct files on the same remote
// device always receive distinct inode numbers. (Remote inode numbers of 2^63
// and above are rare, and are treated as if they were on a separate device.)
// Files on different remote devices map through independent permutations,
// selected by a per-device tweak, so they can only collide if the XOR of their
// remote inode numbers is equal to the XOR of their devices' tweaks (modulo
// 2^63), which happens with probability 2^-63 for each pair of files.
//
// inoMapper is not a security boundary: it hides remote inode numbers from
// casual inspection, but does not attempt to resist cryptanalysis.
type inoMapper struct {
	k0, k1, k2 uint64
}

// newInoMapper returns an inoMapper with a fresh random key.
func newInoMapper() inoMapper {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	return inoMapper{
		k0: binary.LittleEndian.Uint64(b[0:]),
		k1: binary.LittleEndian.Uint64(b[8:]),
		k2: binary.LittleEndian.Uint64(b[16:]),
	}
}

const inoMask = 1<<63 - 1

// ino returns the sentry inode number for key. It may return 0, which callers
// must not use as an inode number.
func (m *inoMapper) ino(key inoKey) uint64 {
	dev := uint64(key.devMajor)<<32 | uint64(key.devMinor)
	tweak := mix64(mix64(dev^m.k2) ^ key.ino>>63)
	return mix63(mix63((key.ino^tweak^m.k0)&inoMask) ^ m.k1&inoMask)
}

// mix64 is the 64-bit finalizer from MurmurHash3. It is a bijection on
// uint64.
func mix64(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}

// mix63 is a bijection on [0, 2^63).
//
// Preconditions: x < 2^63.
func mix63(x uint64) uint64 {
	x ^= x >> 32
	x = (x * 0xbf58476d1ce4e5b9) & inoMask
	x ^= x >> 32
	x = (x * 0x94d049bb133111eb) & inoMask
	x ^= x >> 32
	return x
}
