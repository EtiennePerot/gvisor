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

package systrap

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/testutil"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/usermem"
)

const childEnv = "SYSTRAP_TEST_CHILD"

func TestMain(m *testing.M) {
	switch mode := os.Getenv(childEnv); mode {
	case "":
		cpuid.Initialize()
		os.Exit(m.Run())
	case "stuck":
		for {
			unix.Pause()
		}
	case "hoststall":
		if err := hostStallChild(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown %s: %q\n", childEnv, mode)
		os.Exit(1)
	}
}

// testMemoryManager implements the parts of platform.MemoryManager that
// platformContext.Switch touches on the syscall path. Syscall patching is
// disabled in the tests, so MMap and friends are never reached.
type testMemoryManager struct {
	usermem.IO // Never used.
	as         platform.AddressSpace
}

func (*testMemoryManager) MMap(pkgcontext.Context, memmap.MMapOpts) (hostarch.Addr, error) {
	panic("unexpected MMap call")
}

func (mm *testMemoryManager) AddressSpace() platform.AddressSpace { return mm.as }

func (*testMemoryManager) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	panic("unexpected FindVMAByName call")
}

const userCodeAddr = hostarch.Addr(0x100000)

// newSystrapTest creates a real Systrap instance, maps userCode into a new
// address space, and returns a context ready to Switch into it.
func newSystrapTest(t *testing.T) (*Systrap, platform.AddressSpace, *platformContext, *arch.Context64) {
	t.Helper()

	s, err := New(platform.Options{
		DisableSyscallPatching: true,
		// Only slow-path for now in order to not have to use a real
		// memory manager.
		DisableFastPath: true,
	})
	if err != nil {
		t.Fatalf("failed to create Systrap platform: %v", err)
	}

	as, err := s.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("failed to create address space: %v", err)
	}
	t.Cleanup(as.Release)

	fr, err := s.memoryFile.Allocate(uint64(hostarch.PageSize), pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		t.Fatalf("failed to allocate user code page: %v", err)
	}
	bs, err := s.memoryFile.MapInternal(fr, hostarch.Write)
	if err != nil {
		t.Fatalf("failed to map user code page: %v", err)
	}
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(testutil.UserCode))); err != nil {
		t.Fatalf("failed to write user code: %v", err)
	}
	if err := as.MapFile(userCodeAddr, s.memoryFile, fr, hostarch.AccessType{Read: true, Execute: true}, false); err != nil {
		t.Fatalf("failed to map user code into the stub address space: %v", err)
	}

	pctx := s.NewContext(pkgcontext.Background()).(*platformContext)
	t.Cleanup(pctx.Release)

	ac := arch.New(arch.Host)
	ac.SetIP(uintptr(userCodeAddr))
	return s, as, pctx, ac
}

// TestSwitchThreadIDVisibility runs a real Systrap instance and verifies
// that there is no window during which the ContextState indicates it's being
// worked on AND there is no thread currently working on it.
func TestSwitchThreadIDVisibility(t *testing.T) {
	_, as, pctx, ac := newSystrapTest(t)
	mm := &testMemoryManager{as: as}
	ctx := pkgcontext.Background()
	violations := atomic.Uint64{}
	stop := atomic.Bool{}
	samplerDone := make(chan struct{})
	startSampler := func(shared *sysmsg.ThreadContext) {
		go func() {
			defer close(samplerDone)
			for !stop.Load() {
				a1 := atomic.LoadUint64(&shared.AckedTime)

				// The stub ThreadID must always be set first,
				// and cleared last.
				tid := atomic.LoadUint32(&shared.ThreadID)
				state := shared.State.Get()

				a2 := atomic.LoadUint64(&shared.AckedTime)
				if a1 != 0 && a1 == a2 && state == sysmsg.ContextStateNone && tid == invalidThreadID {
					violations.Add(1)
				}
			}
		}()
	}

	for i := 0; i < 4000; i++ {
		si, _, err := pctx.Switch(ctx, mm, ac, 0)
		if err != nil {
			t.Fatalf("Switch failed at iteration %d: %v (si: %v)", i, err, si)
		}
		if sysno := ac.SyscallNo(); sysno != unix.SYS_GETPID {
			t.Fatalf("unexpected syscall %d at iteration %d", sysno, i)
		}
		ac.SetReturn(0) // Emulate the syscall return value.

		if i == 0 {
			startSampler(pctx.sharedContext.Load().shared)
		}
	}

	stop.Store(true)
	<-samplerDone
	if n := violations.Load(); n != 0 {
		t.Errorf("sampler observed %d acked contexts with an invalid ThreadID; "+
			"the stub published acked_time before ThreadID or cleared ThreadID "+
			"before publishing the context state", n)
	}
}

func TestSpinningQueueLayout(t *testing.T) {
	newSystrapTest(t)
	queueStart := stubContextQueueRegion + stubContextQueueRegionLen
	if stubSpinningThreadQueueAddr < queueStart || stubSpinningThreadQueueAddr+sysmsg.SpinningQueueMemSize > stubContextRegion {
		t.Errorf("spinning queue %#x not in [%#x, %#x)", stubSpinningThreadQueueAddr, queueStart, stubContextRegion)
	}
}

// TestStubFiltersAttached checks the number of seccomp programs and
// no_new_privs on each kind of stub thread.
func TestStubFiltersAttached(t *testing.T) {
	_, as, pctx, ac := newSystrapTest(t)
	// Run once so that the subprocess creates a sysmsg thread.
	if _, _, err := pctx.Switch(pkgcontext.Background(), &testMemoryManager{as: as}, ac, 0); err != nil {
		t.Fatalf("cannot switch: %v", err)
	}
	// Stub processes inherit the seccomp programs of the test process.
	self := procStatus(t, "self")
	selfFilters, ok := self["Seccomp_filters"]
	if !ok {
		t.Skip("Seccomp_filters is not in /proc/self/status (Linux < 5.9)")
	}
	base, err := strconv.Atoi(selfFilters)
	if err != nil {
		t.Fatalf("cannot parse Seccomp_filters %q: %v", selfFilters, err)
	}
	sp := as.(*subprocess)
	syscallFilters, sysmsgFilters := 1, 2
	if seccompNotifyIsSupported {
		syscallFilters, sysmsgFilters = 2, 3
	}
	type stubThread struct {
		name    string
		tid     int32
		filters int
	}
	threads := []stubThread{
		{"source", globalPool.source.syscallThread.thread.tid, 1},
		{"syscall_thread", sp.syscallThread.thread.tid, syscallFilters},
	}
	sp.sysmsgThreadsMu.Lock()
	numSysmsgThreads := len(sp.sysmsgThreads)
	for _, mt := range sp.sysmsgThreads {
		threads = append(threads, stubThread{"sysmsg_thread", mt.thread.tid, sysmsgFilters})
	}
	sp.sysmsgThreadsMu.Unlock()
	if numSysmsgThreads == 0 {
		t.Fatal("the subprocess has no sysmsg thread")
	}
	for _, th := range threads {
		fields := procStatus(t, fmt.Sprint(th.tid))
		if got := fields["NoNewPrivs"]; got != "1" {
			t.Errorf("%s %d: NoNewPrivs = %q, want 1", th.name, th.tid, got)
		}
		if got, want := fields["Seccomp_filters"], fmt.Sprint(base+th.filters); got != want {
			t.Errorf("%s %d: Seccomp_filters = %s, want %s", th.name, th.tid, got, want)
		}
	}
}

// procStatus returns the fields of /proc/<pid>/status.
func procStatus(t *testing.T, pid string) map[string]string {
	t.Helper()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%s/status", pid))
	if err != nil {
		t.Fatalf("cannot read the status of %s: %v", pid, err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	return fields
}

// TestSyscallLoopSpuriousWakeup checks that the futex loop of syscall
// threads still work after a futex wakeup that comes before a syscall
// request.
func TestSyscallLoopSpuriousWakeup(t *testing.T) {
	newSystrapTest(t)
	// The source stub process uses the futex loop.
	s := globalPool.source
	tid := s.syscallThread.thread.tid
	s.syscallThreadMu.Lock()
	woken := 0
	for range 10 {
		woken += futexWakeCount(t, &s.syscallThread.sentryMessage.state)
		time.Sleep(10 * time.Millisecond)
	}
	s.syscallThreadMu.Unlock()
	if woken == 0 {
		t.Fatal("no futex wakeup reached the syscall thread")
	}
	for range 10 {
		if threadDead(t, tid) {
			t.Fatalf("syscall thread %d died after spurious futex wakeups", tid)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// munmap of an unmapped range succeeds.
	if _, err := s.syscall(unix.SYS_MUNMAP, arch.SyscallArgument{Value: 0x10000}, arch.SyscallArgument{Value: hostarch.PageSize}); err != nil {
		t.Fatalf("cannot munmap after spurious futex wakeups: %v", err)
	}
}

// threadDead reports whether the thread tid is a zombie or gone.
func threadDead(t *testing.T, tid int32) bool {
	t.Helper()
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", tid))
	if err != nil {
		return true
	}
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	return len(fields) == 0 || fields[0] == "Z" || fields[0] == "X"
}
