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

// Inode numbers in the gofer filesystem are partitioned into two ranges, both
// below 2^53 so that they are exactly representable as IEEE 754 doubles (e.g.
// JavaScript numbers) and as signed 64-bit integers:
//
//   - [1, 2^52) is used for inode numbers allocated sequentially by
//     filesystem.nextIno(): synthetic files, and remote files whose inode
//     numbers cannot be mapped by inoMapper.
//
//   - [2^52, 2^53) is used for inode numbers derived by inoMapper from remote
//     inode numbers below 2^52.
//
// Thus mapped and allocated inode numbers never collide.
const (
	// inoMappedBit is set in, and only in, inode numbers derived by inoMapper.
	inoMappedBit = 1 << 52

	// inoMappedMask masks the bits that inoMapper permutes.
	inoMappedMask = inoMappedBit - 1
)

// inoMapper derives sentry inode numbers from remote inode keys without
// storing per-file state.
//
// For a given remote device, the mapping from remote inode numbers below 2^52
// to sentry inode numbers is a bijection onto [2^52, 2^53), so distinct files
// on the same remote device always receive distinct inode numbers. Files on
// different remote devices map through independent permutations, selected by a
// per-device tweak, so they can only collide if the XOR of their remote inode
// numbers is equal to the XOR of their devices' tweaks (modulo 2^52), which
// happens with probability 2^-52 for each pair of files. Remote inode numbers
// of 2^52 and above (rare; e.g. overlayfs with xino) are not mapped.
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

// ino returns the sentry inode number for key, which is in [2^52, 2^53).
//
// Preconditions: key.ino < 2^52.
func (m *inoMapper) ino(key inoKey) uint64 {
	dev := uint64(key.devMajor)<<32 | uint64(key.devMinor)
	tweak := mix64(dev ^ m.k2)
	return mix52(mix52((key.ino^tweak^m.k0)&inoMappedMask)^m.k1&inoMappedMask) | inoMappedBit
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

// mix52 is a bijection on [0, 2^52).
//
// Preconditions: x < 2^52.
func mix52(x uint64) uint64 {
	x ^= x >> 26
	x = (x * 0xbf58476d1ce4e5b9) & inoMappedMask
	x ^= x >> 26
	x = (x * 0x94d049bb133111eb) & inoMappedMask
	x ^= x >> 26
	return x
}
