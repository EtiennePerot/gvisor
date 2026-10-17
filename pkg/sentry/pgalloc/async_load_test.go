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
	"errors"
	"sort"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

// saveWithPagesFile saves f's metadata and returns it along with the pages
// file contents. All pages of fr are written with non-zero data, so page i of
// fr is at offset i*PageSize in the pages file.
func saveWithPagesFile(t *testing.T, f *MemoryFile, fr memmap.FileRange) (meta, pages []byte) {
	t.Helper()
	for i := 0; i < int(fr.Length()/hostarch.PageSize); i++ {
		pwritePage(t, f, fr, i, byte(i+1))
	}
	var pagesBuf bytes.Buffer
	saveDone := make(chan error, 1)
	apfs, err := StartAsyncPagesFileSave(stateio.NewIOWriter(&pagesBuf, 1<<20, 1, 1), func(err error) { saveDone <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	var metaBuf bytes.Buffer
	if err := f.SaveTo(context.Background(), &metaBuf, &SaveOpts{PagesFile: apfs}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	apfs.MemoryFilesDone()
	select {
	case err := <-saveDone:
		if err != nil {
			t.Fatalf("async pages file save: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("async pages file save did not complete")
	}
	return metaBuf.Bytes(), pagesBuf.Bytes()
}

// gatedReaderAt blocks all reads until unblock is closed, then fails reads at
// failOff.
type gatedReaderAt struct {
	r       *bytes.Reader
	failOff int64
	unblock chan struct{}
}

func (g *gatedReaderAt) ReadAt(b []byte, off int64) (int, error) {
	<-g.unblock
	if off == g.failOff {
		return 0, errors.New("injected read failure")
	}
	return g.r.ReadAt(b, off)
}

// batchingReader returns completions in batches of two when at least two
// reads are in flight, successful ones first.
type batchingReader struct {
	*stateio.IOReader
	inflight int
}

func (r *batchingReader) AddRead(id int, off int64, df stateio.DestinationFile, fr memmap.FileRange, dst []byte) {
	r.inflight++
	r.IOReader.AddRead(id, off, df, fr, dst)
}

func (r *batchingReader) AddReadv(id int, off int64, total uint64, df stateio.DestinationFile, frs []memmap.FileRange, dsts []unix.Iovec) {
	r.inflight++
	r.IOReader.AddReadv(id, off, total, df, frs, dsts)
}

func (r *batchingReader) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	cs, err := r.IOReader.Wait(cs, max(minCompletions, min(2, r.inflight)))
	r.inflight -= len(cs)
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].Err == nil && cs[j].Err != nil })
	return cs, err
}

// TestAsyncLoadFailureWakesSatisfiedWaiters checks that when a read fails,
// waiters whose pages were loaded by an earlier completion in the same batch
// are still woken, instead of blocking forever in awaitLoad.
func TestAsyncLoadFailureWakesSatisfiedWaiters(t *testing.T) {
	src := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, src)
	meta, pages := saveWithPagesFile(t, src, fr)

	// One page per read and two reads in flight: pages 0 and 1 are read
	// first, and both reads block until unblock is closed. The read of page 1
	// fails; both complete in the same batch, page 0 first.
	ra := &gatedReaderAt{r: bytes.NewReader(pages), failOff: hostarch.PageSize, unblock: make(chan struct{})}
	ar := &batchingReader{IOReader: stateio.NewIOReader(ra, hostarch.PageSize, 1, 2)}
	apflDone := make(chan error, 1)
	apfl, err := StartAsyncPagesFileLoad(ar, func(err error) { apflDone <- err }, nil)
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad: %v", err)
	}
	dst := newSaveTestMemoryFile(t, false)
	if err := dst.LoadFrom(context.Background(), bytes.NewReader(meta), &LoadOpts{PagesFile: apfl}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	apfl.MemoryFilesDone()
	t.Cleanup(func() { dst.DecRef(fr) })

	// Wait for page 0, which is satisfied by the successful completion.
	page0 := memmap.FileRange{fr.Start, fr.Start + hostarch.PageSize}
	done := make(chan error, 1)
	go func() {
		_, err := dst.MapInternal(page0, hostarch.Read)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	close(ra.unblock)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("awaitLoad of a loaded page blocked forever after a failed read in the same batch")
	}
	// Let async page loading shut down before the pages are released.
	select {
	case err := <-apflDone:
		if err == nil {
			t.Errorf("async page loading succeeded, want failure")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("async page loading did not shut down after a failed read")
	}
}
