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
	"gvisor.dev/gvisor/pkg/sync"
)

// saveWithPagesFile saves f's metadata and returns it along with the pages
// file contents. All pages of fr are written with non-zero data, so page i of
// fr is at offset i*PageSize in the pages file.
func saveWithPagesFile(t *testing.T, f *MemoryFile, fr memmap.FileRange) (meta, pages []byte) {
	t.Helper()
	metas, pages := saveAllWithPagesFile(t, []*MemoryFile{f}, []memmap.FileRange{fr})
	return metas[0], pages
}

// saveAllWithPagesFile is like saveWithPagesFile, but saves fs[i] (with pages
// frs[i]) to a single pages file, in order.
func saveAllWithPagesFile(t *testing.T, fs []*MemoryFile, frs []memmap.FileRange) (metas [][]byte, pages []byte) {
	t.Helper()
	var pagesBuf bytes.Buffer
	saveDone := make(chan error, 1)
	apfs, err := StartAsyncPagesFileSave(stateio.NewIOWriter(&pagesBuf, 1<<20, 1, 1), func(err error) { saveDone <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	for i, f := range fs {
		fr := frs[i]
		for i := 0; i < int(fr.Length()/hostarch.PageSize); i++ {
			pwritePage(t, f, fr, i, byte(i+1))
		}
		var metaBuf bytes.Buffer
		if err := f.SaveTo(context.Background(), &metaBuf, &SaveOpts{PagesFile: apfs}); err != nil {
			t.Fatalf("SaveTo: %v", err)
		}
		metas = append(metas, metaBuf.Bytes())
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
	return metas, pagesBuf.Bytes()
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
	apfl, err := StartAsyncPagesFileLoad(ar, func(err error) { apflDone <- err }, nil, AsyncPagesFileLoadOpts{})
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

// TestAsyncLoadFinishesWhenUnloadedPagesBecomeWaste checks that async page
// loading for a MemoryFile completes when its remaining unloaded pages become
// waste while no read for that MemoryFile is in flight.
func TestAsyncLoadFinishesWhenUnloadedPagesBecomeWaste(t *testing.T) {
	srcA := newSaveTestMemoryFile(t, false)
	frA := allocateSaveTestPages(t, srcA)
	srcB := newSaveTestMemoryFile(t, false)
	frB := allocateSaveTestPages(t, srcB)
	metas, pages := saveAllWithPagesFile(t, []*MemoryFile{srcA, srcB}, []memmap.FileRange{frA, frB})

	// One page per read and one read in flight, blocked until unblock is
	// closed: no page of B can be read before all pages of A are.
	ra := &gatedReaderAt{r: bytes.NewReader(pages), failOff: -1, unblock: make(chan struct{})}
	apflDone := make(chan error, 1)
	apfl, err := StartAsyncPagesFileLoad(stateio.NewIOReader(ra, hostarch.PageSize, 1, 1), func(err error) { apflDone <- err }, nil, AsyncPagesFileLoadOpts{})
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad: %v", err)
	}
	dstA := newSaveTestMemoryFile(t, false)
	dstB := newSaveTestMemoryFile(t, false)
	opts := LoadOpts{PagesFile: apfl}
	if err := dstA.LoadFrom(context.Background(), bytes.NewReader(metas[0]), &opts); err != nil {
		t.Fatalf("LoadFrom(A): %v", err)
	}
	t.Cleanup(func() { dstA.DecRef(frA) })
	if err := dstB.LoadFrom(context.Background(), bytes.NewReader(metas[1]), &opts); err != nil {
		t.Fatalf("LoadFrom(B): %v", err)
	}
	apfl.MemoryFilesDone()

	// All of B's pages become waste before any of them is read.
	dstB.DecRef(frB)
	close(ra.unblock)
	select {
	case err := <-apflDone:
		if err != nil {
			t.Fatalf("async page loading failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("async page loading did not complete")
	}
	if dstA.IsAsyncLoading() {
		t.Errorf("A: IsAsyncLoading() = true after async page loading completed")
	}
	if dstB.IsAsyncLoading() {
		t.Errorf("B: IsAsyncLoading() = true after async page loading completed")
	}
}

// steppedReaderAt blocks each read until it receives from release.
type steppedReaderAt struct {
	r       *bytes.Reader
	release chan struct{}
}

func (s *steppedReaderAt) ReadAt(b []byte, off int64) (int, error) {
	<-s.release
	return s.r.ReadAt(b, off)
}

// countingReader tracks the number of reads in flight.
type countingReader struct {
	*stateio.IOReader

	mu          sync.Mutex
	inflight    int
	maxInflight int
	sizes       []uint64
}

func (r *countingReader) add(size uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inflight++
	r.maxInflight = max(r.maxInflight, r.inflight)
	r.sizes = append(r.sizes, size)
}

func (r *countingReader) AddRead(id int, off int64, df stateio.DestinationFile, fr memmap.FileRange, dst []byte) {
	r.add(uint64(len(dst)))
	r.IOReader.AddRead(id, off, df, fr, dst)
}

func (r *countingReader) AddReadv(id int, off int64, total uint64, df stateio.DestinationFile, frs []memmap.FileRange, dsts []unix.Iovec) {
	r.add(total)
	r.IOReader.AddReadv(id, off, total, df, frs, dsts)
}

func (r *countingReader) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	cs, err := r.IOReader.Wait(cs, minCompletions)
	r.mu.Lock()
	r.inflight -= len(cs)
	r.mu.Unlock()
	return cs, err
}

// counts returns the current number of reads in flight, and the maximum
// since the last call to resetMax.
func (r *countingReader) counts() (inflight, maxInflight int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inflight, r.maxInflight
}

func (r *countingReader) resetMax() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxInflight = r.inflight
}

// waitInflight waits for r to have exactly want reads in flight, and for that
// to remain the case for a short time.
func (r *countingReader) waitInflight(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if n, _ := r.counts(); n == want {
			time.Sleep(50 * time.Millisecond)
			if n, _ := r.counts(); n == want {
				return
			}
		}
		if time.Now().After(deadline) {
			n, _ := r.counts()
			t.Fatalf("got %d reads in flight, want %d", n, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestAsyncLoadUnawaitedReadLimits checks the number of reads of pages without
// waiters that async page loading starts with each AsyncPagesFileLoadOpts.
func TestAsyncLoadUnawaitedReadLimits(t *testing.T) {
	const maxParallel = 8
	for _, tc := range []struct {
		name string
		opts AsyncPagesFileLoadOpts
		// Maximum number of reads in flight before and after Unthrottle.
		wantThrottled   int
		wantUnthrottled int
	}{
		{
			name:            "Unlimited",
			opts:            AsyncPagesFileLoadOpts{},
			wantThrottled:   maxParallel,
			wantUnthrottled: maxParallel,
		},
		{
			name:            "Throttled",
			opts:            AsyncPagesFileLoadOpts{Throttled: true},
			wantThrottled:   1,
			wantUnthrottled: maxParallel,
		},
		{
			name:            "Limited",
			opts:            AsyncPagesFileLoadOpts{MaxUnawaitedReads: 2},
			wantThrottled:   2,
			wantUnthrottled: 2,
		},
		{
			name:            "ThrottledThenLimited",
			opts:            AsyncPagesFileLoadOpts{Throttled: true, MaxUnawaitedReads: 2},
			wantThrottled:   1,
			wantUnthrottled: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newSaveTestMemoryFile(t, false)
			fr := allocateSaveTestPages(t, src)
			meta, pages := saveWithPagesFile(t, src, fr)

			// One page per read, so that each page is read separately.
			ra := &steppedReaderAt{r: bytes.NewReader(pages), release: make(chan struct{})}
			ar := &countingReader{IOReader: stateio.NewIOReader(ra, hostarch.PageSize, 1, maxParallel)}
			apflDone := make(chan error, 1)
			apfl, err := StartAsyncPagesFileLoad(ar, func(err error) { apflDone <- err }, nil, tc.opts)
			if err != nil {
				t.Fatalf("StartAsyncPagesFileLoad: %v", err)
			}
			dst := newSaveTestMemoryFile(t, false)
			if err := dst.LoadFrom(context.Background(), bytes.NewReader(meta), &LoadOpts{PagesFile: apfl}); err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			apfl.MemoryFilesDone()
			t.Cleanup(func() { dst.DecRef(fr) })

			// Complete reads one at a time.
			for range 3 {
				ar.waitInflight(t, tc.wantThrottled)
				ra.release <- struct{}{}
			}
			ar.waitInflight(t, tc.wantThrottled)
			if _, got := ar.counts(); got != tc.wantThrottled {
				t.Errorf("before Unthrottle: got up to %d reads in flight, want %d", got, tc.wantThrottled)
			}
			// Unthrottle takes effect when the loader next runs, i.e. when
			// the next read completes.
			ar.resetMax()
			apfl.Unthrottle()
			ra.release <- struct{}{}
			for range 3 {
				ar.waitInflight(t, tc.wantUnthrottled)
				ra.release <- struct{}{}
			}
			ar.waitInflight(t, tc.wantUnthrottled)
			close(ra.release)
			select {
			case err := <-apflDone:
				if err != nil {
					t.Fatalf("async page loading failed: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("async page loading did not complete")
			}
			if _, got := ar.counts(); got != tc.wantUnthrottled {
				t.Errorf("after Unthrottle: got up to %d reads in flight, want %d", got, tc.wantUnthrottled)
			}
			checkLoadedPages(t, dst, fr)
		})
	}
}

// TestAsyncLoadLimitedAwaitedReads checks that reads of pages with waiters are
// not limited by AsyncPagesFileLoadOpts.Throttled and MaxUnawaitedReads.
func TestAsyncLoadLimitedAwaitedReads(t *testing.T) {
	const maxParallel = 8
	src := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, src)
	meta, pages := saveWithPagesFile(t, src, fr)

	ra := &steppedReaderAt{r: bytes.NewReader(pages), release: make(chan struct{})}
	ar := &countingReader{IOReader: stateio.NewIOReader(ra, hostarch.PageSize, 1, maxParallel)}
	apflDone := make(chan error, 1)
	apfl, err := StartAsyncPagesFileLoad(ar, func(err error) { apflDone <- err }, nil, AsyncPagesFileLoadOpts{Throttled: true, MaxUnawaitedReads: 1})
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad: %v", err)
	}
	dst := newSaveTestMemoryFile(t, false)
	if err := dst.LoadFrom(context.Background(), bytes.NewReader(meta), &LoadOpts{PagesFile: apfl}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	apfl.MemoryFilesDone()
	t.Cleanup(func() { dst.DecRef(fr) })

	// The read of page 0 is in flight. Wait for the last 4 pages, each in a
	// separate goroutine. The loader only starts reading them after the next
	// read completes.
	ar.waitInflight(t, 1)
	const numWaiters = 4
	var wg sync.WaitGroup
	for i := range numWaiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			page := uint64(fr.Length()/hostarch.PageSize) - 1 - uint64(i)
			start := fr.Start + page*hostarch.PageSize
			if _, err := dst.MapInternal(memmap.FileRange{start, start + hostarch.PageSize}, hostarch.Read); err != nil {
				t.Errorf("MapInternal(page %d): %v", page, err)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	ra.release <- struct{}{}
	// All awaited pages are read concurrently, but the loader starts no new
	// read of pages without waiters while they are in flight.
	ar.waitInflight(t, numWaiters)
	close(ra.release)
	wg.Wait()
	select {
	case err := <-apflDone:
		if err != nil {
			t.Fatalf("async page loading failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("async page loading did not complete")
	}
	checkLoadedPages(t, dst, fr)
}

// TestAsyncLoadMaxUnawaitedReadBytes checks that
// AsyncPagesFileLoadOpts.MaxUnawaitedReadBytes limits the size of reads of
// pages without waiters, but not of reads of pages with waiters.
func TestAsyncLoadMaxUnawaitedReadBytes(t *testing.T) {
	const maxParallel = 4
	src := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, src)
	meta, pages := saveWithPagesFile(t, src, fr)
	numPages := fr.Length() / hostarch.PageSize

	ra := &steppedReaderAt{r: bytes.NewReader(pages), release: make(chan struct{})}
	ar := &countingReader{IOReader: stateio.NewIOReader(ra, fr.Length(), 1, maxParallel)}
	apflDone := make(chan error, 1)
	apfl, err := StartAsyncPagesFileLoad(ar, func(err error) { apflDone <- err }, nil, AsyncPagesFileLoadOpts{MaxUnawaitedReadBytes: 2*hostarch.PageSize + 1})
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad: %v", err)
	}
	dst := newSaveTestMemoryFile(t, false)
	if err := dst.LoadFrom(context.Background(), bytes.NewReader(meta), &LoadOpts{PagesFile: apfl}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	apfl.MemoryFilesDone()
	t.Cleanup(func() { dst.DecRef(fr) })

	// Reads of pages 0-7 are in flight. Wait for pages 8-15, which are read
	// together after the next read completes.
	ar.waitInflight(t, maxParallel)
	awaited := memmap.FileRange{fr.Start + numPages/2*hostarch.PageSize, fr.End}
	done := make(chan error, 1)
	go func() {
		_, err := dst.MapInternal(awaited, hostarch.Read)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	close(ra.release)
	if err := <-done; err != nil {
		t.Fatalf("MapInternal(%v): %v", awaited, err)
	}
	select {
	case err := <-apflDone:
		if err != nil {
			t.Fatalf("async page loading failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("async page loading did not complete")
	}
	checkLoadedPages(t, dst, fr)

	ar.mu.Lock()
	defer ar.mu.Unlock()
	sawAwaited := false
	for _, size := range ar.sizes {
		switch size {
		case 2 * hostarch.PageSize:
		case awaited.Length():
			sawAwaited = true
		default:
			t.Errorf("got read of %d bytes, want %d or %d bytes", size, 2*hostarch.PageSize, awaited.Length())
		}
	}
	if !sawAwaited {
		t.Errorf("got reads of sizes %v, want one of %d bytes", ar.sizes, awaited.Length())
	}
}

// checkLoadedPages checks that the pages of fr in f have the contents written
// by saveWithPagesFile.
func checkLoadedPages(t *testing.T, f *MemoryFile, fr memmap.FileRange) {
	t.Helper()
	buf := make([]byte, hostarch.PageSize)
	for i := 0; i < int(fr.Length()/hostarch.PageSize); i++ {
		if _, err := unix.Pread(f.FD(), buf, int64(fr.Start)+int64(i*int(hostarch.PageSize))); err != nil {
			t.Fatalf("Pread page %d: %v", i, err)
		}
		if got, want := buf[17], byte(i+1); got != want {
			t.Errorf("page %d: got byte %d, want %d", i, got, want)
		}
	}
}
