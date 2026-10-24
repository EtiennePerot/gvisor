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
	"testing"
)

var (
	allShmemEnabled = []string{"", "always", "within_size", "advise", "never", "deny", "force", "bogus"}
	allDefrag       = []string{"", "always", "defer", "defer+madvise", "madvise", "never", "bogus"}
)

// TestMemfdHugepagesUnchanged checks that, for memfds on hosts without a
// per-size shmem control or with the default "inherit", the memory file huge
// page options are the same as before per-size controls were considered.
func TestMemfdHugepagesUnchanged(t *testing.T) {
	for _, se := range allShmemEnabled {
		for _, hse := range []string{"", "inherit"} {
			for _, defrag := range allDefrag {
				thp := HostTHP{ShmemEnabled: se, HugeShmemEnabled: hse, Defrag: defrag}
				got, gotEnabled := thp.memoryFileHugepages(se)
				var want memoryFileHugepageOpts
				switch se {
				case "advise":
					switch defrag {
					case "always", "defer", "never":
						want.expectHugepages = true
						want.adviseHugepage = true
					}
				case "always", "within_size":
					want.expectHugepages = true
					want.adviseNoHugepage = true
				case "force":
					want.expectHugepages = true
				}
				got.reason = ""
				if got != want || gotEnabled != want.expectHugepages {
					t.Errorf("%+v: got %+v (enabled=%t), want %+v", thp, got, gotEnabled, want)
				}
			}
		}
	}
}

func TestShmemHuge(t *testing.T) {
	for _, test := range []struct {
		shmemEnabled     string
		hugeShmemEnabled string
		mountHuge        string
		want             string
	}{
		{"never", "", "within_size", "within_size"},
		{"never", "inherit", "within_size", "within_size"},
		{"never", "inherit", "always", "always"},
		{"advise", "inherit", "within_size", "within_size"},
		{"always", "inherit", "never", "never"},
		{"deny", "inherit", "within_size", "never"},
		{"deny", "always", "within_size", "never"},
		{"force", "inherit", "never", "force"},
		{"force", "", "never", "force"},
		{"force", "always", "never", "never"},
		{"never", "always", "never", "always"},
		{"never", "within_size", "never", "within_size"},
		{"never", "advise", "within_size", "advise"},
		{"never", "never", "within_size", "never"},
		{"never", "bogus", "within_size", ""},
		{"", "inherit", "within_size", ""},
		{"bogus", "inherit", "within_size", ""},
	} {
		thp := HostTHP{ShmemEnabled: test.shmemEnabled, HugeShmemEnabled: test.hugeShmemEnabled}
		if got := thp.shmemHuge(test.mountHuge); got != test.want {
			t.Errorf("%+v.shmemHuge(%q) = %q, want %q", thp, test.mountHuge, got, test.want)
		}
	}
}
