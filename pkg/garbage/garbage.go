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

// Package garbage temporarily suspends the Go garbage collector.
//
// The garbage collector settings are process-wide. Suspensions are counted, so
// that independent users (e.g. startup and checkpointing) compose: garbage
// collection resumes, with the settings in effect before the first suspension,
// only once every suspension has been released.
package garbage

import (
	"runtime"
	"runtime/debug"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	mu sync.Mutex

	// suspensions is the number of Suspend calls not yet matched by Resume.
	//
	// +checklocks:mu
	suspensions int

	// prevPercent and prevLimit are the GC percent and soft memory limit in
	// effect before the first active suspension.
	//
	// +checklocks:mu
	prevPercent int
	// +checklocks:mu
	prevLimit int64

	// abandoned is true if the previous settings were restored early, because
	// the runtime collected garbage despite the current suspensions.
	//
	// +checklocks:mu
	abandoned bool

	// epoch identifies the current period of suspensions.
	//
	// +checklocks:mu
	epoch uint64
)

// Suspend disables garbage collection until a matching call to Resume.
//
// If memoryLimit is positive, the soft memory limit (see
// runtime/debug.SetMemoryLimit) is lowered to memoryLimit, if it isn't already
// lower, until all suspensions are released. Callers should provide a limit
// unless the suspension is known to be short and to allocate little.
//
// Past this limit, the runtime collects garbage despite the suspension. If it
// does, most of the memory is live and suspending collection no longer saves
// any work, while collecting near the limit could happen very often. So the
// previous settings are then restored right away, and further suspensions have
// no effect until all suspensions are released.
func Suspend(memoryLimit int64) {
	mu.Lock()
	defer mu.Unlock()
	if suspensions == 0 {
		// SetMemoryLimit with a negative value only returns the current
		// limit.
		prevLimit = debug.SetMemoryLimit(-1)
		abandoned = false
	}
	if abandoned {
		suspensions++
		return
	}
	if memoryLimit > 0 {
		// Lower the limit before disabling the GC, so that the GC is
		// never disabled without the limit in place.
		if cur := debug.SetMemoryLimit(-1); memoryLimit < cur {
			debug.SetMemoryLimit(memoryLimit)
		}
	}
	if suspensions == 0 {
		prevPercent = debug.SetGCPercent(-1)
		// The sentinel is unreachable, so the first collection from now
		// on calls collected.
		epoch++
		runtime.AddCleanup(new(sentinel), collected, epoch)
	}
	suspensions++
}

// Resume releases a suspension acquired by Suspend. When no suspensions
// remain, the GC percent and memory limit in effect before the first
// suspension are restored.
func Resume() {
	mu.Lock()
	defer mu.Unlock()
	if suspensions == 0 {
		panic("garbage.Resume without a matching Suspend")
	}
	suspensions--
	if suspensions == 0 && !abandoned {
		restoreLocked()
	}
}

// +checklocks:mu
func restoreLocked() {
	// Re-enable the GC before lifting the limit; see Suspend.
	debug.SetGCPercent(prevPercent)
	debug.SetMemoryLimit(prevLimit)
}

// sentinel contains a pointer so that it isn't allocated by the tiny
// allocator, whose objects may never be cleaned up.
type sentinel struct {
	_ *byte
}

// collected is called after the first collection following the start of the
// given epoch.
func collected(e uint64) {
	mu.Lock()
	defer mu.Unlock()
	if e != epoch || suspensions == 0 || abandoned {
		return
	}
	// Periodic collections don't happen while the GC percent is negative,
	// so this collection was forced by the memory limit (or runtime.GC).
	log.Infof("Garbage collection ran while suspended; resuming it early")
	restoreLocked()
	abandoned = true
}
