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
	"runtime/metrics"
	gtime "time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	ktime "gvisor.dev/gvisor/pkg/sentry/ktime"
)

// The Sentry's Go heap grows with application activity (network buffers,
// dentries, syscall bookkeeping), but when the application goes idle, the Go
// runtime is slow to give that memory back. Garbage stays on the heap until the
// runtime forces a GC after 2 minutes without one, and the background
// scavenger then returns the freed pages to the host over several more
// minutes. Some of the memory also only becomes garbage a while after the
// application goes idle, e.g. TCP endpoints in TIME-WAIT. An idle sandbox can
// thus hold tens of MiB of reclaimable memory for about 5 minutes after each
// burst of activity, and never gives it back if bursts come more often than
// that.
//
// The idle memory releaser closes this gap by calling debug.FreeOSMemory,
// which collects garbage and returns all free heap pages to the host at once:
//
//   - once the application has been quiet for an activity window, which
//     releases the garbage left by the last burst of activity;
//
//   - if the application then stays fully idle, once more after
//     idleMemoryLateReleaseDelay, which releases memory that only became
//     garbage after the application went idle; and
//
//   - while the application stays fully idle, after each GC cycle (such as
//     the runtime's periodic forced GC) that leaves free pages for the
//     scavenger.
//
// Except for the late release, whose garbage can't be measured without a GC,
// it only does so if enough memory can be released for the work to be worth
// it. It never runs while the kernel is paused (e.g. for a checkpoint).
const (
	// idleMemoryReleaseWindow is the window over which the releaser measures
	// application activity. The releaser runs between one and two windows
	// after the application goes quiet.
	idleMemoryReleaseWindow = 10 * gtime.Second

	// idleMemoryReleaseMaxBusy is the maximum CPU clock time that may elapse
	// within idleMemoryReleaseWindow for the application to still count as
	// quiet. Since each wakeup of an otherwise idle kernel accounts at least
	// one CPU clock tick (10ms), this tolerates light periodic activity, such
	// as timers and health checks, of up to about one wakeup per second.
	idleMemoryReleaseMaxBusy = idleMemoryReleaseWindow / 100

	// idleMemoryLateReleaseDelay is the delay between the release when the
	// application goes quiet and the late release. It covers TCP endpoints in
	// TIME-WAIT, which netstack keeps for 60 seconds after the application
	// closes the connection.
	idleMemoryLateReleaseDelay = gtime.Minute

	// idleMemoryReleaseMinBytes is the minimum estimated amount of memory that
	// FreeOSMemory would return to the host for the releaser to run it.
	idleMemoryReleaseMinBytes = 1 << 20
)

// idleMemorySource is the subset of *kernel.Kernel used by the idle memory
// releaser.
type idleMemorySource interface {
	TaskActivity() <-chan struct{}
	CPUClockNow() ktime.Time
	IsPaused() bool
}

// idleMemoryReleaser releases the Sentry's free Go heap memory to the host
// when the application goes idle. See the comment above.
type idleMemoryReleaser struct {
	src      idleMemorySource
	maxBusy  gtime.Duration
	minBytes uint64

	// waitWindow blocks for one activity window. It returns false if stop is
	// closed first.
	waitWindow func(stop <-chan struct{}) bool

	// gcDone receives a value after GC cycles.
	gcDone <-chan struct{}

	// lateRelease returns a channel that receives a value when the late
	// release is due.
	lateRelease func() <-chan gtime.Time

	// releasable estimates how much memory freeOSMemory would release.
	releasable func() uint64

	// freeOSMemory releases memory to the host.
	freeOSMemory func()
}

// startIdleMemoryReleaser starts releasing memory when the kernel goes idle.
// It returns a function that stops the releaser and waits for it to exit.
func startIdleMemoryReleaser(src idleMemorySource) func() {
	gcDone, stopGCNotify := notifyGC()
	r := &idleMemoryReleaser{
		src:        src,
		maxBusy:    idleMemoryReleaseMaxBusy,
		minBytes:   idleMemoryReleaseMinBytes,
		waitWindow: windowWaiter(idleMemoryReleaseWindow),
		gcDone:     gcDone,
		lateRelease: func() <-chan gtime.Time {
			return gtime.After(idleMemoryLateReleaseDelay)
		},
		releasable:   releasableHeapBytes,
		freeOSMemory: runtimedebug.FreeOSMemory,
	}
	stop := r.start()
	return func() {
		stop()
		stopGCNotify()
	}
}

// windowWaiter returns a function that waits for d, or until stop is closed.
func windowWaiter(d gtime.Duration) func(stop <-chan struct{}) bool {
	timer := gtime.NewTimer(d)
	timer.Stop()
	return func(stop <-chan struct{}) bool {
		timer.Reset(d)
		select {
		case <-timer.C:
			return true
		case <-stop:
			timer.Stop()
			return false
		}
	}
}

func (r *idleMemoryReleaser) start() func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { // S/R-SAFE: the releaser skips paused kernels and keeps no state.
		r.run(stop)
		close(done)
	}()
	return func() {
		close(stop)
		<-done
	}
}

func (r *idleMemoryReleaser) run(stop <-chan struct{}) {
	for {
		// Wait until the application has been quiet for a whole window.
		for {
			start := r.src.CPUClockNow()
			if !r.waitWindow(stop) {
				return
			}
			if r.src.CPUClockNow().Sub(start) <= r.maxBusy {
				break
			}
		}
		r.release(false /* force */)

		// Park while the kernel is idle. No task runs while parked, so memory
		// that is freed in the meantime is not about to be reused.
		late := r.lateRelease()
	Parked:
		for {
			select {
			case <-stop:
				return
			case <-r.src.TaskActivity():
				break Parked
			case <-late:
				late = nil
				r.release(true /* force */)
			case <-r.gcDone:
				r.release(false /* force */)
			}
		}
	}
}

// release calls freeOSMemory unless the kernel is paused. Unless force is
// true, it also does nothing if too little memory would be released.
func (r *idleMemoryReleaser) release(force bool) {
	if r.src.IsPaused() {
		return
	}
	n := r.releasable()
	if !force && n < r.minBytes {
		return
	}
	r.freeOSMemory()
	log.Debugf("Released Sentry heap memory while the application is idle (estimated at least %d bytes, forced: %t)", n, force)
}

// gcSentinel is an object whose cleanup runs after each GC cycle. It contains
// a pointer so that it isn't allocated by the tiny allocator, which may delay
// its collection indefinitely.
type gcSentinel struct {
	_ *byte
}

// notifyGC returns a channel that receives a value after GC cycles, and a
// function that stops notifications. Notifications are coalesced if the
// receiver isn't ready.
func notifyGC() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	var stopped atomicbitops.Bool
	var arm func(struct{})
	arm = func(struct{}) {
		if stopped.Load() {
			return
		}
		runtime.AddCleanup(&gcSentinel{}, arm, struct{}{})
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	runtime.AddCleanup(&gcSentinel{}, arm, struct{}{})
	return ch, func() { stopped.Store(true) }
}

// releasableHeapBytes estimates how much memory debug.FreeOSMemory would
// return to the host: free heap pages that the scavenger has not returned yet,
// plus heap memory allocated since the last GC, which is an upper bound on the
// garbage that the GC would free.
func releasableHeapBytes() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/free:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/gc/heap/live:bytes"},
	}
	metrics.Read(samples)
	for _, s := range samples {
		if s.Value.Kind() != metrics.KindUint64 {
			return 0
		}
	}
	free := samples[0].Value.Uint64()
	objects := samples[1].Value.Uint64()
	live := samples[2].Value.Uint64()
	if objects > live {
		free += objects - live
	}
	return free
}
