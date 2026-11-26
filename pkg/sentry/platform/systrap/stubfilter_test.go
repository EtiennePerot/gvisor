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
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/stubfilter"
)

// Stub layout used by the tests.
const (
	testStubStart   = uint64(0x7f0010000000)
	testSysmsgStart = testStubStart + 0x2000
	testROMapEnd    = testStubStart + 0x9000

	// Instruction pointers after a system call instruction in the stub init
	// code, in the sysmsg code, in the guest code, and in the vsyscall page.
	testInitIP     = testStubStart + 0x40
	testSysmsgIP   = testSysmsgStart + 0x80
	testGuestIP    = uint64(0x13370000)
	testVsyscallIP = uint64(0xffffffffff600009)
)

// System call arguments of the stub.
const (
	testCloneStub = uint64(unix.CLONE_FILES | unix.CLONE_PARENT | unix.SIGCHLD)
	testSigstop   = uint64(unix.SIGSTOP)
)

// Seccomp actions.
const (
	allow = uint32(linux.SECCOMP_RET_ALLOW)
	trap  = uint32(linux.SECCOMP_RET_TRAP)
)

// Stub program names.
const (
	progStub    = stubfilter.StubProcessName
	progSysmsg  = stubfilter.SysmsgThreadName
	progSyscall = stubfilter.SyscallThreadName
)

// Programs that apply to each kind of stub thread.
var (
	// Threads with only the StubProcess program: the ptrace thread of the
	// source stub process, syscall threads that use the futex loop, and new
	// sysmsg threads of those syscall threads before the Sentry installs the
	// SysmsgThread program.
	stackSource = []string{progStub}
	// Syscall threads that use seccomp notifications.
	stackSyscall = []string{progStub, progSyscall}
	// Sysmsg threads of stub processes whose syscall thread uses the futex
	// loop.
	stackFutexSysmsg = []string{progStub, progSysmsg}
	// Sysmsg threads of stub processes whose syscall thread uses seccomp
	// notifications.
	stackSysmsg = []string{progStub, progSyscall, progSysmsg}
)

// TestStubFilterPrecompiled checks that rendering the precompiled stub
// programs yields the same bytecode as compiling them with the same values,
// for randomized stub addresses as chosen by stubInit.
func TestStubFilterPrecompiled(t *testing.T) {
	const stubROMapLen = 0x9000
	rendered := map[string][]bpf.Instruction{}
	for range 16 {
		stubStart := rand.Uint64N(1<<47) &^ uint64(hostarch.PageMask)
		stubSysmsgStart := stubStart + 0x5000
		for _, test := range []struct {
			name string
			vars precompiledseccomp.Values
			fn   func(precompiledseccomp.Values) *seccomp.Program
		}{
			{stubfilter.StubProcessName, stubfilter.StubProcessVars(stubStart, stubROMapLen), stubfilter.StubProcess},
			{stubfilter.SysmsgThreadName, stubfilter.SysmsgThreadVars(stubStart, stubSysmsgStart), stubfilter.SysmsgThread},
			{stubfilter.SyscallThreadName, nil, stubfilter.SyscallThread},
		} {
			want, _, err := test.fn(test.vars).Build()
			if err != nil {
				t.Fatalf("%s (stubStart=%#x): cannot build program: %v", test.name, stubStart, err)
			}
			got := renderStubFilter(test.name, test.vars)
			if !slices.Equal(got, want) {
				t.Errorf("%s (stubStart=%#x): rendered precompiled program differs from compiled program:\ngot:  %v\nwant: %v", test.name, stubStart, got, want)
			}
			if prev, ok := rendered[test.name]; ok && test.vars != nil && slices.Equal(got, prev) {
				t.Errorf("%s: rendered program does not depend on stubStart=%#x", test.name, stubStart)
			}
			rendered[test.name] = got
		}
	}
}

// stubFilters contains compiled stub programs.
type stubFilters map[string]bpf.Program

// compileStubFilters renders and compiles the stub programs for the test
// layout.
func compileStubFilters(t *testing.T) stubFilters {
	t.Helper()
	vars := map[string]precompiledseccomp.Values{
		progStub:    stubfilter.StubProcessVars(testStubStart, testROMapEnd-testStubStart),
		progSysmsg:  stubfilter.SysmsgThreadVars(testStubStart, testSysmsgStart),
		progSyscall: nil,
	}
	filters := stubFilters{}
	for name, v := range vars {
		prog, err := bpf.Compile(renderStubFilter(name, v), true)
		if err != nil {
			t.Fatalf("cannot compile %s: %v", name, err)
		}
		filters[name] = prog
	}
	return filters
}

// run returns the action of program prog for the given input.
func (f stubFilters) run(t *testing.T, prog string, auditArch uint32, nr uintptr, ip uint64, args [6]uint64) uint32 {
	t.Helper()
	return runProgram(t, f[prog], auditArch, nr, ip, args)
}

// runProgram returns the action of prog for the given input.
func runProgram(t *testing.T, prog bpf.Program, auditArch uint32, nr uintptr, ip uint64, args [6]uint64) uint32 {
	t.Helper()
	data := linux.SeccompData{
		Nr:                 int32(nr),
		Arch:               auditArch,
		InstructionPointer: ip,
		Args:               args,
	}
	buf := make([]byte, data.SizeBytes())
	ret, err := bpf.Exec[bpf.NativeEndian](prog, seccomp.DataAsBPFInput(&data, buf))
	if err != nil {
		t.Fatalf("cannot execute program: %v", err)
	}
	return ret
}

// runStack returns the action that the kernel takes for a thread with the
// given programs.
func (f stubFilters) runStack(t *testing.T, progs []string, nr uintptr, ip uint64, args [6]uint64) uint32 {
	t.Helper()
	var ret uint32
	for i, prog := range progs {
		r := f.run(t, prog, seccomp.LINUX_AUDIT_ARCH, nr, ip, args)
		// Lower wins.
		if i == 0 || int32(r&linux.SECCOMP_RET_ACTION_FULL) < int32(ret&linux.SECCOMP_RET_ACTION_FULL) {
			ret = r
		}
	}
	return ret
}

// stubFilterCase is a seccomp input and the expected action of one stub
// program.
type stubFilterCase struct {
	prog string
	name string
	nr   uintptr
	ip   uint64
	args [6]uint64
	want uint32
}

// checkStubFilterCases runs each case against the stub programs.
func checkStubFilterCases(t *testing.T, cases []stubFilterCase) {
	t.Helper()
	f := compileStubFilters(t)
	for _, c := range cases {
		if got := f.run(t, c.prog, seccomp.LINUX_AUDIT_ARCH, c.nr, c.ip, c.args); got != c.want {
			t.Errorf("%s/%s: got %#x, want %#x", c.prog, c.name, got, c.want)
		}
	}
}

// TestStubFilterConfinement checks the actions of each stub program
// against the filters.
func TestStubFilterConfinement(t *testing.T) {
	checkStubFilterCases(t, []stubFilterCase{
		// clone
		{progStub, "clone_stub", unix.SYS_CLONE, testInitIP, [6]uint64{testCloneStub}, allow},
		{progStub, "clone_no_parent", unix.SYS_CLONE, testInitIP, [6]uint64{uint64(unix.CLONE_FILES | unix.SIGCHLD)}, trap},

		// prctl
		{progStub, "prctl_pdeathsig", unix.SYS_PRCTL, testInitIP, [6]uint64{unix.PR_SET_PDEATHSIG, uint64(unix.SIGKILL)}, allow},
		{progStub, "prctl_no_new_privs", unix.SYS_PRCTL, testInitIP, [6]uint64{linux.PR_SET_NO_NEW_PRIVS, 1}, trap},

		// System calls that the stub does not make:
		{progStub, "sched_yield", unix.SYS_SCHED_YIELD, testSysmsgIP, [6]uint64{}, trap},
		{progStub, "tkill", unix.SYS_TKILL, testInitIP, [6]uint64{1234, testSigstop}, trap},
		{progStub, "gettid", unix.SYS_GETTID, testInitIP, [6]uint64{}, trap},
		{progStub, "wait4", unix.SYS_WAIT4, testInitIP, [6]uint64{}, trap},

		// SysmsgThread
		{progSysmsg, "rt_sigreturn", unix.SYS_RT_SIGRETURN, testSysmsgIP, [6]uint64{}, allow},
		{progSysmsg, "sched_yield", unix.SYS_SCHED_YIELD, testSysmsgIP, [6]uint64{}, trap},
	})
}

// TestStubFilterBadArch checks that the StubProcess and SysmsgThread programs
// trap system calls of other architectures.
func TestStubFilterBadArch(t *testing.T) {
	f := compileStubFilters(t)
	for _, prog := range []string{progStub, progSysmsg} {
		if got := f.run(t, prog, testBadArch, unix.SYS_RT_SIGRETURN, testSysmsgIP, [6]uint64{}); got != trap {
			t.Errorf("%s: got %#x, want %#x", prog, got, trap)
		}
	}
}

// newTestStub creates a stub process for the test.
// Current OS thread stays locked until end of test.
func newTestStub(t *testing.T) *thread {
	t.Helper()
	newSystrapTest(t)
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	th, err := createStub()
	if err != nil {
		t.Fatalf("cannot create stub: %v", err)
	}
	t.Cleanup(func() {
		// The stub may be in any state, including ptrace exit stop
		// (that `thread.wait` may already have consumed) or reaped,
		// so do not use `thread.destroy`. Resume before each wait,
		// as stopped stubs may have no new event.
		unix.Kill(int(th.tgid), unix.SIGKILL)
		for {
			unix.PtraceCont(int(th.tid), 0)
			var status unix.WaitStatus
			_, err := unix.Wait4(int(th.tid), &status, unix.WALL, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil || status.Exited() || status.Signaled() {
				return
			}
		}
	})
	return th
}

// TestInjectedSyscallRejected checks that syscalls the Sentry injects
// into stub threads fail when blocked by seccomp.
func TestInjectedSyscallRejected(t *testing.T) {
	th := newTestStub(t)
	_, err := th.syscallIgnoreInterrupt(&th.initRegs, unix.SYS_MPROTECT,
		arch.SyscallArgument{Value: uintptr(stubStart)},
		arch.SyscallArgument{Value: hostarch.PageSize},
		arch.SyscallArgument{Value: unix.PROT_READ | unix.PROT_WRITE})
	if err == nil {
		t.Fatal("injected mprotect succeeded, want error")
	}
	if !errors.Is(err, errStubSeccompRejected) {
		t.Errorf("injected mprotect: got error %v, want %v", err, errStubSeccompRejected)
	}
	if want := fmt.Sprintf("cannot inject system call %d", unix.SYS_MPROTECT); !strings.Contains(err.Error(), want) {
		t.Errorf("injected mprotect: got error %q, want it to contain %q", err, want)
	}
}

// TestInjectedSyscallOtherSIGSYS checks that `SIGSYS` from another sender
// (tgkill) is correctly dropped.
func TestInjectedSyscallOtherSIGSYS(t *testing.T) {
	th := newTestStub(t)
	if err := unix.Tgkill(int(th.tgid), int(th.tid), unix.SIGSYS); err != nil {
		t.Fatalf("cannot send SIGSYS: %v", err)
	}
	pid, err := th.syscallIgnoreInterrupt(&th.initRegs, unix.SYS_GETPID)
	if err != nil {
		t.Fatalf("cannot inject getpid after a SIGSYS from tgkill: %v", err)
	}
	if want := uintptr(th.tgid); pid != want {
		t.Errorf("injected getpid: got %d, want %d", pid, want)
	}
	// The SIGSYS must have been delivered (and dropped) during the system call.
	fields := procStatus(t, fmt.Sprint(th.tid))
	for _, k := range []string{"SigPnd", "ShdPnd"} {
		mask, err := strconv.ParseUint(fields[k], 16, 64)
		if err != nil {
			t.Fatalf("cannot parse %s: %v", k, err)
		}
		if mask&(1<<(unix.SIGSYS-1)) != 0 {
			t.Errorf("SIGSYS is still pending in %s", k)
		}
	}
}
