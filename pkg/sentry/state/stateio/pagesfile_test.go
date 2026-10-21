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

package stateio

import "testing"

func TestPagesFileFDMaxReads(t *testing.T) {
	for _, tc := range []struct {
		cpus, want int
	}{
		{cpus: 0, want: 4},
		{cpus: 1, want: 4},
		{cpus: 2, want: 4},
		{cpus: 4, want: 4},
		{cpus: 8, want: 8},
		{cpus: 12, want: 12},
		{cpus: 64, want: 12},
	} {
		if got := PagesFileFDMaxReads(tc.cpus); got != tc.want {
			t.Errorf("PagesFileFDMaxReads(%d) = %d, want %d", tc.cpus, got, tc.want)
		}
	}
}
