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
	"fmt"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/hostmm"
	"gvisor.dev/gvisor/runsc/config"
)

// HostTHP holds host transparent hugepage settings.
type HostTHP struct {
	// ShmemEnabled is the selected option in
	// /sys/kernel/mm/transparent_hugepage/shmem_enabled.
	ShmemEnabled string

	// HugeShmemEnabled is the selected option in
	// /sys/kernel/mm/transparent_hugepage/hugepages-<size>kB/shmem_enabled
	// (see HugeShmemEnabledFile), or empty if the host kernel predates
	// per-size shmem huge page controls.
	HugeShmemEnabled string

	// Defrag is the selected option in
	// /sys/kernel/mm/transparent_hugepage/defrag.
	Defrag string

	// Enabled is the selected option in
	// /sys/kernel/mm/transparent_hugepage/enabled.
	Enabled string
}

// HugeShmemEnabledFile is the path, relative to
// /sys/kernel/mm/transparent_hugepage, of the per-size shmem huge page control
// for huge pages of size hostarch.HugePageSize.
var HugeShmemEnabledFile = fmt.Sprintf("hugepages-%dkB/shmem_enabled", hostarch.HugePageSize>>10)

// MemoryFileTmpfsDir is the path, relative to the sandbox root, at which runsc
// mounts a sandbox-private tmpfs to back the main MemoryFile, if
// HostTHP.MemoryFileTmpfsHuge() says to.
const MemoryFileTmpfsDir = "/runsc-memory"

// shmemHuge returns the policy that determines whether the host kernel backs
// a regular shmem file by huge pages of size hostarch.HugePageSize, if the
// file is on a tmpfs mount with the given huge= option. For memfds, mountHuge
// is the value of shmem_enabled. shmemHuge returns "" if the policy is unknown.
//
// This follows Linux's mm/shmem.c:shmem_allowable_huge_orders(): top-level
// "deny" and "force" override all mounts; otherwise the per-size control
// applies to all mounts, unless it is "inherit", in which case the mount
// option applies. (Kernels without per-size controls behave as if it was
// "inherit".)
func (t HostTHP) shmemHuge(mountHuge string) string {
	switch t.ShmemEnabled {
	case "deny":
		return "never"
	case "force":
		switch t.HugeShmemEnabled {
		case "", "inherit":
			return "force"
		default:
			// Only inherit orders are enabled by top-level "force".
			return "never"
		}
	case "always", "within_size", "advise", "never":
	default:
		return ""
	}
	switch t.HugeShmemEnabled {
	case "", "inherit":
		return mountHuge
	case "always", "within_size", "advise", "never":
		return t.HugeShmemEnabled
	default:
		return ""
	}
}

// tmpfsHugeOption is the huge= option used for the private tmpfs mount
// that backs the main MemoryFile. "within_size" and "always" behave
// identically for the MemoryFile, whose size is always a multiple of its 1 GiB
// chunk size; prefer the more conservative option.
const tmpfsHugeOption = "within_size"

// MemoryFileTmpfsHuge returns the huge= option of the sandbox-private tmpfs
// mount on which the main MemoryFile should be created, or "" if the main
// MemoryFile should be a memfd.
//
// A memfd gets huge pages only if the host's shmem policy allows it. Many
// hosts (including Container-Optimized OS) set shmem_enabled to "never", so
// that the host's own SysV shm, shared anonymous mappings and memfds don't use
// huge pages, while regular tmpfs mounts can still opt in with huge=. On such
// hosts, application memory can only get huge pages if it is backed by a file
// on such a mount.
func (t HostTHP) MemoryFileTmpfsHuge() string {
	if _, enabled := t.memoryFileHugepages(t.ShmemEnabled); enabled {
		// memfds already get huge pages.
		return ""
	}
	if t.shmemHuge(tmpfsHugeOption) != tmpfsHugeOption {
		// huge= is overridden by the host.
		return ""
	}
	switch t.Defrag {
	case "defer", "defer+madvise", "madvise", "never":
		// Huge page allocations for mappings without MADV_HUGEPAGE don't
		// invoke direct compaction.
	case "always":
		// Huge page allocations will invoke direct compaction; this is
		// consistent with host private anonymous memory only if it uses
		// huge pages without MADV_HUGEPAGE as well.
		if t.Enabled != "always" {
			return ""
		}
	default:
		return ""
	}
	return tmpfsHugeOption
}

// memoryFileHugepages returns the huge page options for a MemoryFile created
// on a tmpfs mount with the given huge= option (for memfds, the host's
// shmem_enabled), and whether these options enable huge pages. It also
// returns a description of the decision for logging.
func (t HostTHP) memoryFileHugepages(mountHuge string) (opts memoryFileHugepageOpts, enabled bool) {
	policy := t.shmemHuge(mountHuge)
	opts.reason = fmt.Sprintf("shmem huge page policy is %q", policy)
	switch policy {
	case "always", "within_size":
		// The kernel will default to using huge pages, and we have to
		// explicitly ask for small pages.
		opts.expectHugepages = true
		opts.adviseNoHugepage = true
	case "force":
		// The kernel will ignore MADV_NOHUGEPAGE, so don't bother.
		opts.expectHugepages = true
	case "advise":
		opts.reason += fmt.Sprintf(", host defrag is %q", t.Defrag)
		switch t.Defrag {
		case "always", "defer", "never":
			// Allocations on MADV_HUGEPAGE pages will invoke direct
			// compaction ("always"), wake kcompactd ("defer"), or do
			// neither ("never"), consistent with host private anonymous
			// memory mappings, so using MADV_HUGEPAGE shouldn't cause a
			// regression vs. running natively.
			opts.expectHugepages = true
			opts.adviseHugepage = true
		default:
			// "defer+madvise", "madvise": Allocations on MADV_HUGEPAGE
			// pages may invoke direct compaction whereas allocations on
			// host private anonymous memory mappings will not, so using
			// MADV_HUGEPAGE may degrade performance. Other values are
			// unknown.
		}
	}
	return opts, opts.expectHugepages
}

// memoryFileHugepageOpts are the huge page-related subset of
// pgalloc.MemoryFileOpts.
type memoryFileHugepageOpts struct {
	expectHugepages  bool
	adviseHugepage   bool
	adviseNoHugepage bool
	reason           string
}

// ChooseMemoryFileTmpfsHuge returns the huge= option of the sandbox-private
// tmpfs mount on which the main MemoryFile should be created, or "" if the
// main MemoryFile should be a memfd.
func ChooseMemoryFileTmpfsHuge(conf *config.Config, t HostTHP) string {
	switch v := conf.TestOnlyMemoryFileTmpfsHuge; v {
	case "":
	case "memfd":
		return ""
	default:
		return v
	}
	if !conf.AppHugePages {
		return ""
	}
	return t.MemoryFileTmpfsHuge()
}

// ReadHostTHP returns the host's transparent hugepage settings. Settings that
// can't be read are left empty.
func ReadHostTHP() HostTHP {
	read := func(name string) string {
		val, _ := hostmm.ReadTransparentHugepageEnum(name)
		return val
	}
	return HostTHP{
		ShmemEnabled:     read("shmem_enabled"),
		HugeShmemEnabled: read(HugeShmemEnabledFile),
		Defrag:           read("defrag"),
		Enabled:          read("enabled"),
	}
}
