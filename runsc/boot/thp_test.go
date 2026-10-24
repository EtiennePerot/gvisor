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

	"gvisor.dev/gvisor/runsc/config"
)

var (
	allShmemEnabled     = []string{"", "always", "within_size", "advise", "never", "deny", "force", "bogus"}
	allHugeShmemEnabled = []string{"", "inherit", "always", "within_size", "advise", "never", "bogus"}
	allDefrag           = []string{"", "always", "defer", "defer+madvise", "madvise", "never", "bogus"}
	allEnabled          = []string{"", "always", "madvise", "never"}
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

func TestMemoryFileTmpfsHuge(t *testing.T) {
	for _, test := range []struct {
		name string
		thp  HostTHP
		want string
	}{
		{
			name: "COS default",
			thp:  HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "inherit", Defrag: "madvise", Enabled: "madvise"},
			want: "within_size",
		},
		{
			name: "kernel without per-size controls",
			thp:  HostTHP{ShmemEnabled: "never", Defrag: "madvise", Enabled: "always"},
			want: "within_size",
		},
		{
			name: "THP disabled for anonymous memory",
			thp:  HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "inherit", Defrag: "madvise", Enabled: "never"},
			want: "within_size",
		},
		{
			name: "advise without usable defrag",
			thp:  HostTHP{ShmemEnabled: "advise", HugeShmemEnabled: "inherit", Defrag: "defer+madvise", Enabled: "madvise"},
			want: "within_size",
		},
		{
			name: "advise with usable defrag",
			thp:  HostTHP{ShmemEnabled: "advise", HugeShmemEnabled: "inherit", Defrag: "defer", Enabled: "madvise"},
			want: "",
		},
		{
			name: "memfds already huge",
			thp:  HostTHP{ShmemEnabled: "within_size", HugeShmemEnabled: "inherit", Defrag: "madvise", Enabled: "madvise"},
			want: "",
		},
		{
			name: "memfds huge by per-size control",
			thp:  HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "always", Defrag: "madvise", Enabled: "madvise"},
			want: "",
		},
		{
			name: "per-size never",
			thp:  HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "never", Defrag: "madvise", Enabled: "madvise"},
			want: "",
		},
		{
			name: "per-size advise",
			thp:  HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "advise", Defrag: "madvise", Enabled: "madvise"},
			want: "",
		},
		{
			name: "deny",
			thp:  HostTHP{ShmemEnabled: "deny", HugeShmemEnabled: "inherit", Defrag: "madvise", Enabled: "always"},
			want: "",
		},
		{
			name: "force",
			thp:  HostTHP{ShmemEnabled: "force", HugeShmemEnabled: "inherit", Defrag: "madvise", Enabled: "always"},
			want: "",
		},
		{
			name: "direct compaction, anonymous memory madvise",
			thp:  HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "inherit", Defrag: "always", Enabled: "madvise"},
			want: "",
		},
		{
			name: "direct compaction, anonymous memory always",
			thp:  HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "inherit", Defrag: "always", Enabled: "always"},
			want: "within_size",
		},
		{
			name: "unknown shmem_enabled",
			thp:  HostTHP{HugeShmemEnabled: "inherit", Defrag: "madvise", Enabled: "madvise"},
			want: "",
		},
		{
			name: "unknown defrag",
			thp:  HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "inherit", Enabled: "madvise"},
			want: "",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.thp.MemoryFileTmpfsHuge(); got != test.want {
				t.Errorf("%+v.MemoryFileTmpfsHuge() = %q, want %q", test.thp, got, test.want)
			}
		})
	}
}

// TestMemoryFileTmpfsHugeEnablesHugepages checks that whenever
// MemoryFileTmpfsHuge chooses a tmpfs, the memory file gets huge pages, and
// that it chooses a tmpfs only if a memfd wouldn't get them.
func TestMemoryFileTmpfsHugeEnablesHugepages(t *testing.T) {
	for _, se := range allShmemEnabled {
		for _, hse := range allHugeShmemEnabled {
			for _, defrag := range allDefrag {
				for _, enabled := range allEnabled {
					thp := HostTHP{ShmemEnabled: se, HugeShmemEnabled: hse, Defrag: defrag, Enabled: enabled}
					huge := thp.MemoryFileTmpfsHuge()
					if huge == "" {
						continue
					}
					if _, memfdEnabled := thp.memoryFileHugepages(se); memfdEnabled {
						t.Errorf("%+v: chose tmpfs huge=%q, but memfds get huge pages", thp, huge)
					}
					if opts, enabled := thp.memoryFileHugepages(huge); !enabled || !opts.adviseNoHugepage {
						t.Errorf("%+v: tmpfs huge=%q gets options %+v", thp, huge, opts)
					}
				}
			}
		}
	}
}

func TestChooseMemoryFileTmpfsHuge(t *testing.T) {
	cos := HostTHP{ShmemEnabled: "never", HugeShmemEnabled: "inherit", Defrag: "madvise", Enabled: "madvise"}
	for _, test := range []struct {
		appHugePages bool
		override     string
		want         string
	}{
		{true, "", "within_size"},
		{false, "", ""},
		{true, "memfd", ""},
		{true, "always", "always"},
		{false, "never", "never"},
	} {
		conf := &config.Config{AppHugePages: test.appHugePages, TestOnlyMemoryFileTmpfsHuge: test.override}
		if got := ChooseMemoryFileTmpfsHuge(conf, cos); got != test.want {
			t.Errorf("AppHugePages=%t override=%q: got %q, want %q", test.appHugePages, test.override, got, test.want)
		}
	}
}
