// Copyright 2018 The gVisor Authors.
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
	"bytes"
	"fmt"
	"sort"
	"time"

	"gvisor.dev/gvisor/pkg/gohacks"
)

// CollectStats controls whether Save and Load collect per-type timing
// statistics (see Stats). Timing every object is a noticeable fraction of the
// cost of Save and Load, so this is off by default; runsc enables it with
// debug logging.
//
// It must not be changed while Save or Load is running.
var CollectStats = false

type statEntry struct {
	count uint
	total time.Duration
}

// Stats tracks encode / decode timing.
//
// This currently provides a meaningful String function and no other way to
// extract stats about individual types.
//
// Stats are only collected if CollectStats is set.
//
// All exported receivers accept nil.
type Stats struct {
	// byType contains a breakdown of time spent by type.
	//
	// This is indexed *directly* by typeID, including zero.
	byType []statEntry

	// stack contains objects in progress.
	stack []typeID

	// names contains type names.
	//
	// This is also indexed *directly* by typeID, including zero, which we
	// hard-code as "state.default". This is only resolved by calling fini
	// on the stats object.
	names []string

	// last is the monotonic time of the last sample.
	last int64

	// enabled is true if stats are being collected.
	enabled bool
}

// init initializes statistics.
func (s *Stats) init() {
	s.enabled = CollectStats
	if !s.enabled {
		return
	}
	s.last = gohacks.Nanotime()
	s.stack = append(s.stack, 0)
}

// fini finalizes statistics.
func (s *Stats) fini(resolve func(id typeID) string) {
	if !s.enabled {
		return
	}
	s.done()

	// Resolve all type names.
	s.names = make([]string, len(s.byType))
	s.names[0] = "state.default" // See above.
	for id := typeID(1); int(id) < len(s.names); id++ {
		s.names[id] = resolve(id)
	}
}

// sample adds the samples to the given object.
func (s *Stats) sample(id typeID) {
	now := gohacks.Nanotime()
	if len(s.byType) <= int(id) {
		// Allocate all the missing entries in one fell swoop.
		s.byType = append(s.byType, make([]statEntry, 1+int(id)-len(s.byType))...)
	}
	s.byType[id].total += time.Duration(now - s.last)
	s.last = now
}

// start starts a sample.
//
// Preconditions: s.enabled.
func (s *Stats) start(id typeID) {
	last := s.stack[len(s.stack)-1]
	s.sample(last)
	s.stack = append(s.stack, id)
}

// done finishes the current sample.
//
// Preconditions: s.enabled.
func (s *Stats) done() {
	last := s.stack[len(s.stack)-1]
	s.sample(last)
	s.byType[last].count++
	s.stack = s.stack[:len(s.stack)-1]
}

type sliceEntry struct {
	name  string
	entry *statEntry
}

// String returns a table representation of the stats.
func (s *Stats) String() string {
	if !s.enabled {
		return "(not collected)"
	}
	// Build a list of stat entries.
	ss := make([]sliceEntry, 0, len(s.byType))
	for id := 0; id < len(s.names); id++ {
		ss = append(ss, sliceEntry{
			name:  s.names[id],
			entry: &s.byType[id],
		})
	}

	// Sort by total time (descending).
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].entry.total > ss[j].entry.total
	})

	// Print the stat results.
	var (
		buf   bytes.Buffer
		count uint
		total time.Duration
	)
	buf.WriteString("\n")
	fmt.Fprintf(&buf, "% 16s | % 8s | % 16s | %s\n", "total", "count", "per", "type")
	buf.WriteString("-----------------+----------+------------------+----------------\n")
	for _, se := range ss {
		if se.entry.count == 0 {
			// Since we store all types linearly, we are not
			// guaranteed that any entry actually has time.
			continue
		}
		count += se.entry.count
		total += se.entry.total
		per := se.entry.total / time.Duration(se.entry.count)
		fmt.Fprintf(&buf, "% 16s | %8d | % 16s | %s\n",
			se.entry.total, se.entry.count, per, se.name)
	}
	buf.WriteString("-----------------+----------+------------------+----------------\n")
	fmt.Fprintf(&buf, "% 16s | % 8d | % 16s | [all]",
		total, count, total/time.Duration(count))
	return buf.String()
}
