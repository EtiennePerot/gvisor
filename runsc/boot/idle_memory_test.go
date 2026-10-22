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

package boot

import (
	"runtime"
	runtimedebug "runtime/debug"
	"testing"
	gtime "time"

	ktime "gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sync"
)

// fakeIdleSource is an idleMemorySource whose activity, CPU clock and pause
// state are controlled by the test. It also drives the releaser's activity
// windows and GC notifications, so that tests are deterministic.
type fakeIdleSource struct {
	mu      sync.Mutex
	running bool
	clock   gtime.Duration
	paused  bool
	// activity is returned by TaskActivity while no task is running.
	activity chan struct{}

	// parked receives a value when the releaser parks.
	parked chan struct{}
	// windowStarted receives a value when the releaser starts an activity
	// window; the window ends when the test sends to windowEnd.
	windowStarted chan struct{}
	windowEnd     chan struct{}
	// gcDone notifies the releaser of GC cycles.
	gcDone chan struct{}
	// late makes the late release due.
	late chan gtime.Time
	// released receives the estimate for each release.
	released chan uint64

	releasable uint64
}

func newFakeIdleSource() *fakeIdleSource {
	return &fakeIdleSource{
		running:       true,
		activity:      make(chan struct{}),
		parked:        make(chan struct{}, 1),
		windowStarted: make(chan struct{}),
		windowEnd:     make(chan struct{}),
		gcDone:        make(chan struct{}),
		late:          make(chan gtime.Time),
		released:      make(chan uint64, 10),
		releasable:    4 << 20,
	}
}

func (f *fakeIdleSource) TaskActivity() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.running {
		return closedTaskActivity
	}
	select {
	case f.parked <- struct{}{}:
	default:
	}
	return f.activity
}

var closedTaskActivity = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

func (f *fakeIdleSource) CPUClockNow() ktime.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ktime.FromNanoseconds(f.clock.Nanoseconds())
}

func (f *fakeIdleSource) IsPaused() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.paused
}

func (f *fakeIdleSource) set(fn func(f *fakeIdleSource)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// wake makes a task run, waking a parked releaser.
func (f *fakeIdleSource) wake() {
	f.set(func(f *fakeIdleSource) {
		f.running = true
		close(f.activity)
		f.activity = make(chan struct{})
	})
}

func (f *fakeIdleSource) start(t *testing.T) {
	t.Helper()
	r := &idleMemoryReleaser{
		src:      f,
		maxBusy:  idleMemoryReleaseMaxBusy,
		minBytes: idleMemoryReleaseMinBytes,
		waitWindow: func(stop <-chan struct{}) bool {
			select {
			case f.windowStarted <- struct{}{}:
			case <-stop:
				return false
			}
			select {
			case <-f.windowEnd:
				return true
			case <-stop:
				return false
			}
		},
		gcDone: f.gcDone,
		lateRelease: func() <-chan gtime.Time {
			return f.late
		},
		releasable: func() uint64 {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.releasable
		},
		freeOSMemory: func() {
			f.mu.Lock()
			n := f.releasable
			f.releasable = 0
			f.mu.Unlock()
			f.released <- n
		},
	}
	t.Cleanup(r.start())
}

// window runs one activity window during which the CPU clock advances by
// busy, and fn is called.
func (f *fakeIdleSource) window(t *testing.T, busy gtime.Duration, fn func(f *fakeIdleSource)) {
	t.Helper()
	select {
	case <-f.windowStarted:
	case <-gtime.After(10 * gtime.Second):
		t.Fatalf("releaser did not start an activity window")
	}
	f.set(func(f *fakeIdleSource) {
		f.clock += busy
		fn(f)
	})
	f.windowEnd <- struct{}{}
}

func goIdle(f *fakeIdleSource) { f.running = false }

func noChange(*fakeIdleSource) {}

func (f *fakeIdleSource) waitParked(t *testing.T) {
	t.Helper()
	select {
	case <-f.parked:
	case <-gtime.After(10 * gtime.Second):
		t.Fatalf("releaser did not park")
	}
}

// lateRelease makes the late release due, and waits until the releaser has
// handled it.
func (f *fakeIdleSource) lateRelease(t *testing.T) {
	t.Helper()
	f.late <- gtime.Time{}
	f.waitParked(t)
}

// gc notifies the releaser of a GC cycle, and waits until it has handled it.
func (f *fakeIdleSource) gc(t *testing.T) {
	t.Helper()
	f.gcDone <- struct{}{}
	f.waitParked(t)
}

// wantReleases returns a function that checks the number of releases. It is
// meant to be called at the start of a window, after the releaser has handled
// the previous one.
func wantReleases(t *testing.T, want int) func(f *fakeIdleSource) {
	return func(f *fakeIdleSource) {
		if got := len(f.released); got != want {
			t.Errorf("got %d releases, want %d", got, want)
		}
	}
}

func (f *fakeIdleSource) wantReleases(t *testing.T, want int) {
	t.Helper()
	if got := len(f.released); got != want {
		t.Errorf("got %d releases, want %d", got, want)
	}
}

func TestIdleMemoryReleaserReleasesOnceAfterActivity(t *testing.T) {
	f := newFakeIdleSource()
	f.start(t)

	// The application is busy: no release.
	f.window(t, idleMemoryReleaseWindow/2, noChange)
	f.window(t, idleMemoryReleaseWindow/2, noChange)
	// The application goes quiet: one release, then the releaser parks
	// without starting more windows.
	f.window(t, 0, goIdle)
	f.waitParked(t)
	f.wantReleases(t, 1)

	// Another burst of activity followed by idleness releases again.
	f.set(func(f *fakeIdleSource) { f.releasable = 8 << 20 })
	f.wake()
	f.window(t, idleMemoryReleaseWindow, noChange)
	f.window(t, 0, goIdle)
	f.waitParked(t)
	f.wantReleases(t, 2)
}

func TestIdleMemoryReleaserToleratesLightActivity(t *testing.T) {
	f := newFakeIdleSource()
	f.start(t)

	// Activity just below the threshold counts as quiet, even if tasks are
	// still waking up periodically.
	f.window(t, idleMemoryReleaseMaxBusy, noChange)
	// The releaser keeps monitoring in case memory becomes releasable again,
	// but has nothing to release.
	f.window(t, idleMemoryReleaseMaxBusy, wantReleases(t, 1))
	// Memory that becomes releasable, e.g. after a GC, is released at the end
	// of the next quiet window.
	f.window(t, idleMemoryReleaseMaxBusy+1, func(f *fakeIdleSource) {
		f.releasable = 2 << 20
	})
	f.window(t, idleMemoryReleaseMaxBusy, wantReleases(t, 1))
	f.window(t, 0, wantReleases(t, 2))
}

func TestIdleMemoryReleaserSkipsSmallReleases(t *testing.T) {
	f := newFakeIdleSource()
	f.set(func(f *fakeIdleSource) { f.releasable = idleMemoryReleaseMinBytes - 1 })
	f.start(t)

	f.window(t, 0, goIdle)
	f.waitParked(t)
	f.gc(t)
	f.wantReleases(t, 0)
}

func TestIdleMemoryReleaserReleasesAfterGCWhileIdle(t *testing.T) {
	f := newFakeIdleSource()
	f.start(t)

	f.window(t, 0, goIdle)
	f.waitParked(t)
	f.wantReleases(t, 1)
	// A GC cycle that leaves nothing to release does nothing.
	f.gc(t)
	f.wantReleases(t, 1)
	// A GC cycle that frees memory while the application is idle, e.g. the
	// runtime's periodic GC after TCP endpoints left TIME-WAIT, releases it.
	f.set(func(f *fakeIdleSource) { f.releasable = 16 << 20 })
	f.gc(t)
	f.wantReleases(t, 2)
	f.gc(t)
	f.wantReleases(t, 2)
}

func TestIdleMemoryReleaserLateRelease(t *testing.T) {
	f := newFakeIdleSource()
	f.start(t)

	f.window(t, 0, goIdle)
	f.waitParked(t)
	f.wantReleases(t, 1)
	// The late release happens even if nothing seems releasable, since the
	// garbage it is after can't be measured without a GC.
	f.lateRelease(t)
	f.wantReleases(t, 2)
	// It happens only once per idle period.
	select {
	case f.late <- gtime.Time{}:
		t.Errorf("releaser waited for a second late release")
	case <-gtime.After(100 * gtime.Millisecond):
	}
	// After more activity, the next idle period gets its own late release.
	f.wake()
	f.window(t, 0, goIdle)
	f.waitParked(t)
	f.wantReleases(t, 2)
	f.lateRelease(t)
	f.wantReleases(t, 3)
}

func TestIdleMemoryReleaserSkipsPausedKernel(t *testing.T) {
	f := newFakeIdleSource()
	f.start(t)

	// A paused kernel (e.g. for a checkpoint) looks idle, but must not be
	// disturbed, even by GCs during the checkpoint.
	f.window(t, 0, func(f *fakeIdleSource) {
		f.running = false
		f.paused = true
	})
	f.waitParked(t)
	f.gc(t)
	f.lateRelease(t)
	f.wantReleases(t, 0)

	// Once the kernel resumes and goes idle again, memory is released.
	f.set(func(f *fakeIdleSource) { f.paused = false })
	f.wake()
	f.window(t, 0, goIdle)
	f.waitParked(t)
	f.wantReleases(t, 1)
}

func TestIdleMemoryReleaserStops(t *testing.T) {
	for _, tc := range []struct {
		name    string
		running bool
	}{
		{name: "parked", running: false},
		{name: "monitoring", running: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIdleSource()
			f.set(func(f *fakeIdleSource) { f.running = tc.running })
			r := &idleMemoryReleaser{
				src:         f,
				gcDone:      f.gcDone,
				lateRelease: func() <-chan gtime.Time { return f.late },
			}
			// Use the real window wait, which must also return on stop.
			r.waitWindow = windowWaiter(gtime.Hour)
			stop := r.start()
			done := make(chan struct{})
			go func() {
				stop()
				close(done)
			}()
			select {
			case <-done:
			case <-gtime.After(10 * gtime.Second):
				t.Fatalf("releaser did not stop")
			}
		})
	}
}

func TestIdleMemoryNotifyGC(t *testing.T) {
	ch, stop := notifyGC()
	defer stop()
	for i := 0; i < 3; i++ {
		runtime.GC()
		select {
		case <-ch:
		case <-gtime.After(10 * gtime.Second):
			t.Fatalf("no notification after GC %d", i)
		}
	}
}

var idleMemoryTestSink [][]byte

func TestIdleMemoryReleasableHeapBytes(t *testing.T) {
	// Keep the GC from collecting the garbage below before it is measured.
	defer runtimedebug.SetGCPercent(runtimedebug.SetGCPercent(-1))
	runtimedebug.FreeOSMemory()
	if got, want := releasableHeapBytes(), uint64(idleMemoryReleaseMinBytes); got >= want {
		t.Errorf("releasableHeapBytes() after FreeOSMemory = %d, want < %d", got, want)
	}
	for i := 0; i < 128; i++ {
		idleMemoryTestSink = append(idleMemoryTestSink, make([]byte, 64<<10))
	}
	idleMemoryTestSink = nil
	if got, want := releasableHeapBytes(), uint64(7<<20); got < want {
		t.Errorf("releasableHeapBytes() after allocating 8 MiB of garbage = %d, want >= %d", got, want)
	}
}
