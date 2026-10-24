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

//go:build !pagesize_64k

package pgalloc

import (
	"bytes"
	"context"
	"io"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

func newSaveTestMemoryFile(t *testing.T, diskBacked bool) *MemoryFile {
	t.Helper()
	return newSaveTestMemoryFileOpts(t, diskBacked, false /* expectHugepages */)
}

func newSaveTestMemoryFileOpts(t *testing.T, diskBacked, expectHugepages bool) *MemoryFile {
	t.Helper()
	var file *os.File
	if diskBacked {
		var err error
		if file, err = os.CreateTemp(t.TempDir(), "pgalloc-save-test"); err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
	} else {
		fd, err := memutil.CreateMemFD("pgalloc-save-test", 0)
		if err != nil {
			t.Fatalf("CreateMemFD: %v", err)
		}
		file = os.NewFile(uintptr(fd), "pgalloc-save-test")
	}
	f, err := NewMemoryFile(file, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		DiskBackedFile:          diskBacked,
		ExpectHugepages:         expectHugepages,
	})
	if err != nil {
		file.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)
	return f
}

func allocateSaveTestPages(t *testing.T, f *MemoryFile) memmap.FileRange {
	t.Helper()
	return allocateSaveTestPagesN(t, f, 16)
}

func allocateSaveTestPagesN(t *testing.T, f *MemoryFile, pages uint64) memmap.FileRange {
	t.Helper()
	fr, err := f.Allocate(pages*uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	t.Cleanup(func() { f.DecRef(fr) })
	return fr
}

func pwritePage(t *testing.T, f *MemoryFile, fr memmap.FileRange, page int, b byte) {
	t.Helper()
	buf := make([]byte, hostarch.PageSize)
	buf[17] = b
	if _, err := unix.Pwrite(f.FD(), buf, int64(fr.Start)+int64(page*int(hostarch.PageSize))); err != nil {
		t.Fatalf("Pwrite page %d: %v", page, err)
	}
}

func TestHostFileDataSeeker(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 2, 1)
	pwritePage(t, f, fr, 3, 1)
	pwritePage(t, f, fr, 9, 1)
	pwritePage(t, f, fr, 12, 0)
	page := func(n uint64) uint64 { return fr.Start + n*uint64(hostarch.PageSize) }
	d := f.newHostFileDataSeeker()
	for _, call := range []struct {
		off  uint64
		want memmap.FileRange
	}{
		{off: page(0), want: memmap.FileRange{page(2), page(4)}},
		{off: page(3), want: memmap.FileRange{page(3), page(4)}},
		{off: page(4), want: memmap.FileRange{page(9), page(10)}},
		{off: page(10), want: memmap.FileRange{page(12), page(13)}},
		{off: page(13), want: memmap.FileRange{f.TotalSize(), f.TotalSize()}},
		{off: page(15), want: memmap.FileRange{f.TotalSize(), f.TotalSize()}},
	} {
		got, err := d.dataAtOrAfter(call.off)
		if err != nil || got != call.want {
			t.Errorf("dataAtOrAfter(%#x): got (%v, %v), want (%v, nil)", call.off, got, err, call.want)
		}
	}
}

func TestSaveToPreservesContents(t *testing.T) {
	for _, tc := range []struct {
		name          string
		diskBacked    bool
		exclude       bool
		wantCommitted uint64
	}{
		{name: "memfd", wantCommitted: 2 * uint64(hostarch.PageSize)},
		{name: "memfd excluding committed zero pages", exclude: true, wantCommitted: uint64(hostarch.PageSize)},
		{name: "disk-backed", diskBacked: true, wantCommitted: 2 * uint64(hostarch.PageSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSaveTestMemoryFile(t, tc.diskBacked)
			fr := allocateSaveTestPages(t, f)
			pwritePage(t, f, fr, 2, 1)
			pwritePage(t, f, fr, 13, 2)
			if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{}); err != nil {
				t.Fatalf("first SaveTo: %v", err)
			}
			pwritePage(t, f, fr, 9, 0)
			pwritePage(t, f, fr, 13, 0)
			want := make([]byte, fr.Length())
			want[2*hostarch.PageSize+17] = 1

			var checkpoint bytes.Buffer
			if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{ExcludeCommittedZeroPages: tc.exclude}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}
			if got := f.knownCommittedBytes; got != tc.wantCommitted {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, tc.wantCommitted)
			}

			restored := newSaveTestMemoryFile(t, tc.diskBacked)
			if err := restored.LoadFrom(context.Background(), &checkpoint, &LoadOpts{}); err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			t.Cleanup(func() { restored.DecRef(fr) })
			restored.forEachMappingSlice(fr, func(bs []byte) {
				if !bytes.Equal(bs, want) {
					t.Error("restored contents differ from saved contents")
				}
			})
		})
	}
}

// hasHostData returns true if any part of fr is allocated in f's file.
func hasHostData(t *testing.T, f *MemoryFile, fr memmap.FileRange) bool {
	t.Helper()
	off, err := unix.Seek(f.FD(), int64(fr.Start), unix.SEEK_DATA)
	if err == unix.ENXIO {
		return false
	}
	if err != nil {
		t.Fatalf("lseek(SEEK_DATA): %v", err)
	}
	return uint64(off) < fr.End
}

func TestSaveToPagesFileReleaseAfterWrite(t *testing.T) {
	for _, tc := range []struct {
		name            string
		release         bool
		expectHugepages bool
	}{
		{name: "keep"},
		{name: "release", release: true},
		{name: "release with huge pages", release: true, expectHugepages: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Use a range that is larger than apsReleaseBatchBytes and isn't
			// hugepage-aligned in length, so that releasing happens in
			// multiple batches and must handle partial huge pages.
			pages := 4*int(hostarch.HugePageSize/hostarch.PageSize) + 64
			f := newSaveTestMemoryFileOpts(t, false /* diskBacked */, tc.expectHugepages)
			fr := allocateSaveTestPagesN(t, f, uint64(pages))
			want := make([]byte, fr.Length())
			for i := 0; i < pages; i++ {
				// Leave some pages zero so that the saved ranges are not
				// all contiguous.
				if i%5 == 3 {
					continue
				}
				// Commit some zero pages, which are not written but must
				// still be released.
				if i%7 == 5 {
					pwritePage(t, f, fr, i, 0)
					continue
				}
				pwritePage(t, f, fr, i, byte(i+1))
				want[i*hostarch.PageSize+17] = byte(i + 1)
			}

			// Use small writes and several parallel operations so that
			// saving involves many operations, some of which complete out of
			// order.
			var pagesFile bytes.Buffer
			aw := stateio.NewIOWriter(&pagesFile, 16*uint64(hostarch.PageSize), 16 /* maxRanges */, 4 /* maxParallel */)
			saveDone := make(chan error, 1)
			apfs, err := StartAsyncPagesFileSave(aw, func(err error) { saveDone <- err })
			if err != nil {
				t.Fatalf("StartAsyncPagesFileSave: %v", err)
			}
			var metadata bytes.Buffer
			err = f.SaveTo(context.Background(), &metadata, &SaveOpts{
				PagesFile:         apfs,
				ReleaseAfterWrite: tc.release,
				DiscardAfterSave:  tc.release,
			})
			apfs.MemoryFilesDone()
			if saveErr := <-saveDone; saveErr != nil {
				t.Fatalf("async page saving: %v", saveErr)
			}
			if err != nil {
				t.Fatalf("SaveTo: %v", err)
			}

			if got := hasHostData(t, f, fr); got == tc.release {
				t.Errorf("after saving with ReleaseAfterWrite=%t: MemoryFile has host data: %t", tc.release, got)
			}
			if !tc.release {
				f.forEachMappingSlice(fr, func(bs []byte) {
					if !bytes.Equal(bs, want) {
						t.Error("MemoryFile contents changed by saving")
					}
				})
			}

			restored := newSaveTestMemoryFileOpts(t, false /* diskBacked */, tc.expectHugepages)
			ar := stateio.NewIOReader(bytes.NewReader(pagesFile.Bytes()), 16*uint64(hostarch.PageSize), 16 /* maxRanges */, 4 /* maxParallel */)
			loadDone := make(chan error, 1)
			apfl, err := StartAsyncPagesFileLoad(ar, func(err error) { loadDone <- err }, nil /* timeline */)
			if err != nil {
				t.Fatalf("StartAsyncPagesFileLoad: %v", err)
			}
			err = restored.LoadFrom(context.Background(), &metadata, &LoadOpts{PagesFile: apfl})
			apfl.MemoryFilesDone()
			if loadErr := <-loadDone; loadErr != nil {
				t.Fatalf("async page loading: %v", loadErr)
			}
			if err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			t.Cleanup(func() { restored.DecRef(fr) })
			restored.forEachMappingSlice(fr, func(bs []byte) {
				if !bytes.Equal(bs, want) {
					t.Error("restored contents differ from saved contents")
				}
			})
		})
	}
}

// hostDataPages returns the indices of pages in fr that are committed in f's
// host file.
func hostDataPages(t *testing.T, f *MemoryFile, fr memmap.FileRange) []int {
	t.Helper()
	var pages []int
	d := f.newHostFileDataSeeker()
	for off := fr.Start; off < fr.End; {
		data, err := d.dataAtOrAfter(off)
		if err != nil {
			t.Fatalf("dataAtOrAfter(%#x): %v", off, err)
		}
		for ; data.Start < min(data.End, fr.End); data.Start += uint64(hostarch.PageSize) {
			pages = append(pages, int((data.Start-fr.Start)/uint64(hostarch.PageSize)))
		}
		off = max(data.End, off+uint64(hostarch.PageSize))
	}
	return pages
}

func TestSaveToDiscardAfterSave(t *testing.T) {
	for _, tc := range []struct {
		name         string
		discard      bool
		wantHostData []int
	}{
		{name: "resume", wantHostData: []int{2, 12}},
		{name: "discard", discard: true, wantHostData: []int{2, 3, 4, 9, 12}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSaveTestMemoryFile(t, false)
			fr := allocateSaveTestPages(t, f)
			pwritePage(t, f, fr, 2, 1)
			pwritePage(t, f, fr, 3, 0)
			pwritePage(t, f, fr, 4, 0)
			pwritePage(t, f, fr, 9, 0)
			pwritePage(t, f, fr, 12, 2)
			want := make([]byte, fr.Length())
			want[2*hostarch.PageSize+17] = 1
			want[12*hostarch.PageSize+17] = 2

			var checkpoint bytes.Buffer
			if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{DiscardAfterSave: tc.discard}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}
			// Zero pages are accounted as uncommitted, whether or not they
			// are decommitted.
			if got, want := f.knownCommittedBytes, 2*uint64(hostarch.PageSize); got != want {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, want)
			}
			if got := hostDataPages(t, f, fr); !slices.Equal(got, tc.wantHostData) {
				t.Errorf("host data pages after SaveTo: got %v, want %v", got, tc.wantHostData)
			}
			f.forEachMappingSlice(fr, func(bs []byte) {
				if !bytes.Equal(bs, want) {
					t.Error("contents changed by SaveTo")
				}
			})

			restored := newSaveTestMemoryFile(t, false)
			if err := restored.LoadFrom(context.Background(), &checkpoint, &LoadOpts{}); err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			t.Cleanup(func() { restored.DecRef(fr) })
			if got, want := restored.knownCommittedBytes, 2*uint64(hostarch.PageSize); got != want {
				t.Errorf("restored knownCommittedBytes: got %d, want %d", got, want)
			}
			restored.forEachMappingSlice(fr, func(bs []byte) {
				if !bytes.Equal(bs, want) {
					t.Error("restored contents differ from saved contents")
				}
			})
		})
	}
}

func TestSaveToDiscardAfterSaveDiskBacked(t *testing.T) {
	// Without SEEK_DATA/SEEK_HOLE, scanning may commit pages that were not
	// committed before, so zero pages must still be decommitted to avoid
	// increasing memory usage during saving.
	f := newSaveTestMemoryFile(t, true)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 2, 1)
	pwritePage(t, f, fr, 3, 0)
	pwritePage(t, f, fr, 4, 0)
	var st unix.Stat_t
	if err := unix.Fstat(f.FD(), &st); err != nil {
		t.Fatalf("Fstat: %v", err)
	}
	blocksBefore := st.Blocks
	if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{DiscardAfterSave: true}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	if err := unix.Fstat(f.FD(), &st); err != nil {
		t.Fatalf("Fstat: %v", err)
	}
	if st.Blocks >= blocksBefore {
		t.Errorf("SaveTo did not decommit zero pages: allocated blocks %d before, %d after", blocksBefore, st.Blocks)
	}
}
