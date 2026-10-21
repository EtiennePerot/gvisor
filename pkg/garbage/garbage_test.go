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

package garbage

import (
	"math"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func gcPercent() int {
	p := debug.SetGCPercent(-1)
	debug.SetGCPercent(p)
	return p
}

func memoryLimit() int64 {
	return debug.SetMemoryLimit(-1)
}

// withSettings sets the GC percent and memory limit for the duration of a
// test.
func withSettings(t *testing.T, percent int, limit int64) {
	t.Helper()
	oldPercent := debug.SetGCPercent(percent)
	oldLimit := debug.SetMemoryLimit(limit)
	t.Cleanup(func() {
		debug.SetGCPercent(oldPercent)
		debug.SetMemoryLimit(oldLimit)
	})
}

func check(t *testing.T, when string, wantPercent int, wantLimit int64) {
	t.Helper()
	if got := gcPercent(); got != wantPercent {
		t.Errorf("%s: GC percent = %d, want %d", when, got, wantPercent)
	}
	if got := memoryLimit(); got != wantLimit {
		t.Errorf("%s: memory limit = %d, want %d", when, got, wantLimit)
	}
}

func TestSuspendResume(t *testing.T) {
	withSettings(t, 37, math.MaxInt64)
	Suspend(0)
	check(t, "suspended without limit", -1, math.MaxInt64)
	Resume()
	check(t, "resumed", 37, math.MaxInt64)
}

func TestSuspendLimit(t *testing.T) {
	withSettings(t, 100, 1<<30)
	Suspend(256 << 20)
	check(t, "suspended", -1, 256<<20)
	Resume()
	check(t, "resumed", 100, 1<<30)
}

func TestSuspendKeepsLowerLimit(t *testing.T) {
	withSettings(t, 100, 64<<20)
	Suspend(256 << 20)
	check(t, "suspended", -1, 64<<20)
	Resume()
	check(t, "resumed", 100, 64<<20)
}

func TestSuspendNests(t *testing.T) {
	withSettings(t, 50, 1<<30)
	Suspend(0)
	Suspend(512 << 20)
	check(t, "two suspensions", -1, 512<<20)
	Suspend(768 << 20)
	check(t, "three suspensions", -1, 512<<20)
	// Releasing suspensions in any order keeps the GC off until the last
	// one is released.
	Resume()
	Resume()
	check(t, "one suspension left", -1, 512<<20)
	Resume()
	check(t, "all released", 50, 1<<30)

	// A new suspension after all were released starts afresh.
	Suspend(0)
	check(t, "suspended again", -1, 1<<30)
	Resume()
	check(t, "released again", 50, 1<<30)
}

func TestConcurrent(t *testing.T) {
	withSettings(t, 80, math.MaxInt64)
	done := make(chan struct{})
	const goroutines, iterations = 8, 1000
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < iterations; j++ {
				Suspend(0)
				Resume()
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
	check(t, "after concurrent use", 80, math.MaxInt64)
}

func TestUnmatchedResumePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Resume without a matching Suspend did not panic")
		}
	}()
	Resume()
}

// waitForResume forces collections until the GC percent is want.
func waitForResume(t *testing.T, want int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); gcPercent() != want; {
		if time.Now().After(deadline) {
			t.Fatalf("GC percent still %d after collections, want %d", gcPercent(), want)
		}
		// Stands in for a collection forced by the memory limit.
		runtime.GC()
		time.Sleep(time.Millisecond)
	}
}

func TestCollectionAbandonsSuspension(t *testing.T) {
	withSettings(t, 50, 1<<40)
	Suspend(1 << 39)
	Suspend(0)
	waitForResume(t, 50)
	check(t, "after a collection", 50, 1<<40)

	// Suspensions are counted, but have no effect until all are released.
	Suspend(1 << 38)
	check(t, "suspended after abandoning", 50, 1<<40)
	Resume()
	Resume()
	debug.SetGCPercent(60)
	Resume()
	check(t, "all released", 60, 1<<40)

	// A new suspension after all were released starts afresh.
	Suspend(1 << 39)
	check(t, "suspended again", -1, 1<<39)
	Resume()
	check(t, "released again", 60, 1<<40)
}

func TestStaleCollectionIgnored(t *testing.T) {
	withSettings(t, 100, math.MaxInt64)
	Suspend(0)
	Resume()
	Suspend(0)
	mu.Lock()
	stale := epoch - 1
	mu.Unlock()
	collected(stale)
	check(t, "after a collection from an earlier epoch", -1, math.MaxInt64)
	Resume()
	check(t, "resumed", 100, math.MaxInt64)
}
