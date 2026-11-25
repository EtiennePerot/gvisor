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

//go:build amd64
// +build amd64

package systrap

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// testBadArch is a compat architecture.
const testBadArch = unix.AUDIT_ARCH_I386

// TestStubFilterConfinementAMD64 checks the AMD64-only rules of the stub
// programs.
func TestStubFilterConfinementAMD64(t *testing.T) {
	checkStubFilterCases(t, []stubFilterCase{
		{progStub, "arch_prctl_set_fs", unix.SYS_ARCH_PRCTL, testSysmsgIP, [6]uint64{linux.ARCH_SET_FS, 0x1000}, allow},
		{progStub, "arch_prctl_set_cpuid", unix.SYS_ARCH_PRCTL, testSysmsgIP, [6]uint64{linux.ARCH_SET_CPUID, 0}, trap},
		{progSysmsg, "arch_prctl_set_fs", unix.SYS_ARCH_PRCTL, testSysmsgIP, [6]uint64{linux.ARCH_SET_FS, 0x1000}, allow},
		{progSysmsg, "arch_prctl_set_cpuid", unix.SYS_ARCH_PRCTL, testSysmsgIP, [6]uint64{linux.ARCH_SET_CPUID, 0}, trap},
	})
}

// TestStubFilterVsyscall checks that the stub programs trap the vsyscall
// system calls, from the vsyscall page and from other code.
func TestStubFilterVsyscall(t *testing.T) {
	f := compileStubFilters(t)
	for _, nr := range []uintptr{unix.SYS_GETTIMEOFDAY, unix.SYS_TIME, unix.SYS_GETCPU} {
		for _, ip := range []uint64{testVsyscallIP, testVsyscallIP + 0x400, testVsyscallIP + 0x800, testGuestIP, testInitIP, testSysmsgIP} {
			for _, prog := range []string{progStub, progSysmsg} {
				if got := f.run(t, prog, seccomp.LINUX_AUDIT_ARCH, nr, ip, [6]uint64{}); got != trap {
					t.Errorf("%s: system call %d from IP %#x: got %#x, want %#x", prog, nr, ip, got, trap)
				}
			}
			for _, stack := range [][]string{stackSource, stackSyscall, stackFutexSysmsg, stackSysmsg} {
				if got := f.runStack(t, stack, nr, ip, [6]uint64{}); got != trap {
					t.Errorf("%v: system call %d from IP %#x: got %#x, want %#x", stack, nr, ip, got, trap)
				}
			}
		}
	}
}

// TestStubFilterX32 checks that the stub programs trap x32 system calls.
func TestStubFilterX32(t *testing.T) {
	const x32 = 0x40000000 // __X32_SYSCALL_BIT
	f := compileStubFilters(t)
	for _, nr := range []uintptr{unix.SYS_GETPID, unix.SYS_CLONE, unix.SYS_EXIT_GROUP, unix.SYS_FUTEX, unix.SYS_RT_SIGRETURN} {
		for _, ip := range []uint64{testInitIP, testSysmsgIP, testGuestIP} {
			for _, stack := range [][]string{stackSource, stackSyscall, stackFutexSysmsg, stackSysmsg} {
				if got := f.runStack(t, stack, x32|nr, ip, [6]uint64{testCloneStub}); got != trap {
					t.Errorf("%v: x32 system call %d from IP %#x: got %#x, want %#x", stack, nr, ip, got, trap)
				}
			}
		}
	}
}
