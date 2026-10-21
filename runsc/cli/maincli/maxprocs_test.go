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

package maincli

import (
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	maxprocsPkg = "gvisor.dev/gvisor/runsc/cli/maxprocs"

	// maxAllocBeforeMaxprocs is the maximum number of bytes that package
	// initialization may allocate before package maxprocs is initialized. It
	// is far below the 4 MB heap size that triggers the first garbage
	// collection cycle.
	maxAllocBeforeMaxprocs = 16 << 10
)

// TestMaxProcsInitOrder checks that package maxprocs bounds GOMAXPROCS early
// in package initialization: before the first garbage collection cycle, and
// before packages that allocate significantly are initialized.
func TestMaxProcsInitOrder(t *testing.T) {
	// Re-execute this test binary without running any test, and trace package
	// initialization and garbage collection.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(env string) bool {
		return strings.HasPrefix(env, "GOMAXPROCS=") || strings.HasPrefix(env, "GODEBUG=")
	}), "GODEBUG=inittrace=1,gctrace=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v failed: %v, output:\n%s", cmd, err, out)
	}
	// Lines look like:
	// init gvisor.dev/gvisor/runsc/cli/maxprocs @0.42 ms, 0.50 ms clock, 1640 bytes, 7 allocs
	allocated := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "gc ") {
			t.Fatalf("garbage collection before %s init: %q\noutput:\n%s", maxprocsPkg, line, out)
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "init" {
			continue
		}
		if fields[1] == maxprocsPkg {
			return
		}
		i := slices.Index(fields, "bytes,")
		if i < 1 {
			t.Fatalf("failed to parse init trace line %q", line)
		}
		n, err := strconv.Atoi(fields[i-1])
		if err != nil {
			t.Fatalf("failed to parse init trace line %q: %v", line, err)
		}
		if allocated += n; allocated > maxAllocBeforeMaxprocs {
			t.Fatalf("package initialization allocated %d bytes before %s init (through %s), want at most %d\noutput:\n%s", allocated, maxprocsPkg, fields[1], maxAllocBeforeMaxprocs, out)
		}
	}
	t.Fatalf("no init trace for %s, output:\n%s", maxprocsPkg, out)
}
