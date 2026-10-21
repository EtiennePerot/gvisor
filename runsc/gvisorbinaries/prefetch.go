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
	"encoding/binary"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/log"
)

const (
	// prefetchSamples is the number of offsets of a file that isCold
	// checks.
	prefetchSamples = 16

	// prefetchStep is the size of each prefetch request. The kernel caps
	// posix_fadvise(POSIX_FADV_WILLNEED) requests to the larger of the
	// device's readahead window and maximum I/O size, so larger requests
	// would be truncated. The default readahead window is 128 KiB.
	prefetchStep = 128 << 10
)

// Prefetch starts reading the parts of the executable at path that running it
// touches into the page cache, unless they appear to be there already. It does
// not wait for the reads to complete.
//
// When the page cache is cold (the first sandbox on a host, after a binary
// upgrade, or after memory pressure evicted them), executing runsc's large Go
// binaries otherwise reads them by page faults, roughly one readahead window
// at a time, on the critical path of sandbox creation and restore. Prefetching
// submits all reads upfront instead, so they complete at disk bandwidth and
// these page faults find their pages already read or in flight.
//
// The page cache pages that Prefetch reads are charged to the caller's memory
// cgroup.
//
// When the file is cached, which is the common case, Prefetch costs a few
// microseconds (see isCold). Errors are ignored, since prefetching is only an
// optimization.
func Prefetch(path string) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 {
		unix.Close(fd)
		return
	}
	ranges := loadedRanges(fd, st.Size)
	if ranges == nil {
		ranges = [][2]int64{{0, st.Size}}
	}
	if !isCold(fd, ranges) {
		unix.Close(fd)
		return
	}
	log.Infof("Prefetching %q into the page cache", path)
	go func() {
		defer unix.Close(fd)
		for _, r := range ranges {
			for off := r[0]; off < r[1]; off += prefetchStep {
				// This returns once the reads are submitted.
				if err := unix.Fadvise(fd, off, min(prefetchStep, r[1]-off), unix.FADV_WILLNEED); err != nil {
					log.Debugf("Prefetching %q: %v", path, err)
					return
				}
			}
		}
	}()
}

// isCold returns true if any of prefetchSamples offsets spread over ranges is
// not in the page cache. It reads one byte at each sampled offset with
// RWF_NOWAIT, which fails with EAGAIN rather than wait for I/O. It returns
// false if the file's filesystem doesn't support RWF_NOWAIT (EOPNOTSUPP);
// as of Linux 6.12, these include tmpfs, where files are always in memory,
// and overlayfs.
func isCold(fd int, ranges [][2]int64) bool {
	var total int64
	for _, r := range ranges {
		total += r[1] - r[0]
	}
	var b [1]byte
	iov := [][]byte{b[:]}
	for _, pos := range sampleOffsets(ranges, total, prefetchSamples) {
		if _, err := unix.Preadv2(fd, iov, pos, unix.RWF_NOWAIT); err != nil {
			return err == unix.EAGAIN
		}
	}
	return false
}

// sampleOffsets returns n file offsets spread evenly over ranges, whose total
// length is total, including the first and last byte.
func sampleOffsets(ranges [][2]int64, total int64, n int) []int64 {
	offs := make([]int64, 0, n)
	r := 0
	var before int64 // Total length of ranges[:r].
	for i := 0; i < n && total > 0; i++ {
		pos := (total - 1) * int64(i) / int64(max(n-1, 1))
		for pos >= before+ranges[r][1]-ranges[r][0] {
			before += ranges[r][1] - ranges[r][0]
			r++
		}
		offs = append(offs, ranges[r][0]+pos-before)
	}
	return offs
}

// ELF constants used by loadedRanges.
const (
	elfHeaderSize    = 64
	elfPhdrSize      = 56
	elfMaxPhdrs      = 64
	elfClass64       = 2
	elfDataLSB       = 1
	elfPTLoad        = 1
	elfPhoffOffset   = 0x20
	elfPhentsizeOffs = 0x36
	elfPhnumOffset   = 0x38
)

// loadedRanges returns the file ranges [start, end) of the PT_LOAD segments of
// the 64-bit little-endian ELF file fd of the given size, which are the parts
// of it that executing it may read, or nil if fd is not such a file. This
// excludes debugging information, which is about a third of a Go binary.
//
// It parses the ELF program headers by hand to avoid linking debug/elf into
// runsc.
func loadedRanges(fd int, size int64) [][2]int64 {
	var hdr [elfHeaderSize]byte
	if n, err := unix.Pread(fd, hdr[:], 0); err != nil || n != len(hdr) {
		return nil
	}
	if string(hdr[:4]) != "\x7fELF" || hdr[4] != elfClass64 || hdr[5] != elfDataLSB {
		return nil
	}
	phoff := binary.LittleEndian.Uint64(hdr[elfPhoffOffset:])
	phentsize := int(binary.LittleEndian.Uint16(hdr[elfPhentsizeOffs:]))
	phnum := int(binary.LittleEndian.Uint16(hdr[elfPhnumOffset:]))
	if phentsize < elfPhdrSize || phnum == 0 || phnum > elfMaxPhdrs || phoff > uint64(size) {
		return nil
	}
	phdrs := make([]byte, phentsize*phnum)
	if n, err := unix.Pread(fd, phdrs, int64(phoff)); err != nil || n != len(phdrs) {
		return nil
	}
	var ranges [][2]int64
	for i := 0; i < phnum; i++ {
		ph := phdrs[i*phentsize:]
		if binary.LittleEndian.Uint32(ph) != elfPTLoad {
			continue
		}
		off := binary.LittleEndian.Uint64(ph[8:])
		filesz := binary.LittleEndian.Uint64(ph[32:])
		if off > uint64(size) || filesz > uint64(size)-off {
			return nil
		}
		if filesz > 0 {
			ranges = append(ranges, [2]int64{int64(off), int64(off + filesz)})
		}
	}
	return ranges
}
