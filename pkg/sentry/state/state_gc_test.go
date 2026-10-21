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

package state

import (
	"math"
	"runtime/debug"
	"testing"

	"gvisor.dev/gvisor/pkg/garbage"
)

func TestSaveGCMemoryLimit(t *testing.T) {
	for _, tc := range []struct {
		used int64
		want int64
	}{
		{used: 0, want: saveGCMinHeadroom},
		{used: 20 << 20, want: (20 << 20) + saveGCMinHeadroom},
		{used: saveGCMinHeadroom, want: 2 * saveGCMinHeadroom},
		{used: 1 << 30, want: 2 << 30},
		{used: math.MaxInt64 / 2, want: math.MaxInt64 - 1},
		{used: math.MaxInt64/2 + 1, want: math.MaxInt64},
		{used: math.MaxInt64, want: math.MaxInt64},
	} {
		if got := saveGCMemoryLimit(tc.used); got != tc.want {
			t.Errorf("saveGCMemoryLimit(%d) = %d, want %d", tc.used, got, tc.want)
		}
	}
}

func TestSuspendGCForSave(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int64
	}{
		{name: "no limit", limit: math.MaxInt64},
		// A lower limit set by the embedder must be kept.
		{name: "low limit", limit: 64 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldPercent := debug.SetGCPercent(100)
			oldLimit := debug.SetMemoryLimit(tc.limit)
			defer func() {
				debug.SetGCPercent(oldPercent)
				debug.SetMemoryLimit(oldLimit)
			}()

			suspendGCForSave()
			percent := debug.SetGCPercent(-1)
			limit := debug.SetMemoryLimit(-1)
			garbage.Resume()

			if percent != -1 {
				t.Errorf("during save: GC percent = %d, want -1", percent)
			}
			if limit > tc.limit || limit < min(tc.limit, saveGCMinHeadroom) {
				t.Errorf("during save: memory limit = %d, want in [%d, %d]", limit, min(tc.limit, saveGCMinHeadroom), tc.limit)
			}
			if tc.limit == math.MaxInt64 && limit == math.MaxInt64 {
				t.Errorf("during save: no memory limit set")
			}
			if got := debug.SetGCPercent(100); got != 100 {
				t.Errorf("after save: GC percent = %d, want 100", got)
			}
			if got := debug.SetMemoryLimit(-1); got != tc.limit {
				t.Errorf("after save: memory limit = %d, want %d", got, tc.limit)
			}
		})
	}
}
