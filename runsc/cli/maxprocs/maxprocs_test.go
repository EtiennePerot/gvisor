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

package maxprocs

import (
	"runtime"
	"testing"
)

func TestBound(t *testing.T) {
	for _, tc := range []struct {
		cur    int
		envSet bool
		want   int
	}{
		{cur: 1, want: 0},
		{cur: 2, want: 0},
		{cur: maxProcs, want: 0},
		{cur: maxProcs + 1, want: 0},
		{cur: 96, want: 0},
		{cur: threshold, want: 0},
		{cur: threshold + 1, want: maxProcs},
		{cur: 192, want: maxProcs},
		{cur: 192, envSet: true, want: 0},
		{cur: 2, envSet: true, want: 0},
	} {
		if got := bound(tc.cur, tc.envSet); got != tc.want {
			t.Errorf("bound(%d, %t) = %d, want %d", tc.cur, tc.envSet, got, tc.want)
		}
	}
}

func TestInitAndRestore(t *testing.T) {
	if lowered {
		if got := runtime.GOMAXPROCS(0); got != maxProcs {
			t.Errorf("GOMAXPROCS after init = %d, want %d", got, maxProcs)
		}
	}
	Restore()
	if lowered {
		t.Errorf("lowered = true after Restore")
	}
	if got := runtime.GOMAXPROCS(0); got > runtime.NumCPU() {
		t.Errorf("GOMAXPROCS after Restore = %d, want at most NumCPU = %d", got, runtime.NumCPU())
	}
}
