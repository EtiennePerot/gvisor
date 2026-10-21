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
	"runtime/metrics"

	"gvisor.dev/gvisor/pkg/garbage"
)

// saveGCMinHeadroom is the minimum amount by which Go runtime memory may grow
// during a save before the garbage collector runs. See suspendGCForSave.
const saveGCMinHeadroom = 128 << 20

// saveGCMemoryLimit returns the soft memory limit to use while the garbage
// collector is suspended for a save, given the memory currently used by the
// Go runtime (as accounted for by the memory limit).
//
// The headroom scales with current usage so that, like with the default
// GOGC=100, memory may roughly double before the first collection. It is at
// least saveGCMinHeadroom so that small sandboxes are usually saved without
// collecting at all. If the limit is reached, the suspension ends (see
// garbage.Suspend).
func saveGCMemoryLimit(used int64) int64 {
	headroom := max(used, saveGCMinHeadroom)
	if used > math.MaxInt64-headroom {
		return math.MaxInt64
	}
	return used + headroom
}

// suspendGCForSave suspends garbage collection, bounded by a soft memory limit
// computed by saveGCMemoryLimit. The caller must call garbage.Resume when the
// save is done.
//
// Saving the kernel allocates heavily (state encoding) while all tasks are
// stopped and little memory becomes garbage, so GC cycles during a save mostly
// add latency and compete for CPU with the save itself.
func suspendGCForSave() {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples)
	used := int64(samples[0].Value.Uint64() - samples[1].Value.Uint64())
	garbage.Suspend(saveGCMemoryLimit(used))
}
