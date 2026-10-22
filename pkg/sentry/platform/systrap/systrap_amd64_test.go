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
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// clockUserCode is a user program that loops over:
//
//	%r12 = clock_gettime(%r14, %r13);
//	getpid();
var clockUserCode = []byte{
	0xb8, 0xe4, 0x00, 0x00, 0x00, // mov $SYS_clock_gettime, %eax
	0x4c, 0x89, 0xf7, // mov %r14, %rdi
	0x4c, 0x89, 0xee, // mov %r13, %rsi
	0x0f, 0x05, // syscall
	0x49, 0x89, 0xc4, // mov %rax, %r12
	0xb8, 0x27, 0x00, 0x00, 0x00, // mov $SYS_getpid, %eax
	0x0f, 0x05, // syscall
	0xeb, 0xe7, // jmp back to the start
}

const userDataAddr = hostarch.Addr(0x200000)

func TestThreadCPUClock(t *testing.T) {
	s, as, pctx, ac := newSystrapTestWithCode(t, clockUserCode)
	mm := &testMemoryManager{as: as}
	ctx := pkgcontext.Background()

	// Map a writable data page for the timespec.
	fr, err := s.memoryFile.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		t.Fatalf("failed to allocate user data page: %v", err)
	}
	bs, err := s.memoryFile.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("failed to map user data page: %v", err)
	}
	if err := as.MapFile(userDataAddr, s.memoryFile, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("failed to map user data page into the stub address space: %v", err)
	}
	readTimespec := func(t *testing.T) (int64, int64) {
		var buf [16]byte
		if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:])), bs); err != nil {
			t.Fatalf("failed to read timespec: %v", err)
		}
		return int64(binary.LittleEndian.Uint64(buf[:8])), int64(binary.LittleEndian.Uint64(buf[8:]))
	}

	// switchToSyscall runs the application until its next syscall that is
	// not handled by the stub, and returns that syscall's number.
	switchToSyscall := func(t *testing.T) uintptr {
		t.Helper()
		if si, _, err := pctx.Switch(ctx, mm, ac, 0); err != nil {
			t.Fatalf("Switch failed: %v (si: %v)", err, si)
		}
		sysno := ac.SyscallNo()
		ac.SetReturn(0) // Emulate the syscall.
		return sysno
	}

	// The application starts at the start of the loop, like after getpid.
	lastSysno := uintptr(unix.SYS_GETPID)
	for _, tc := range []struct {
		name    string
		enabled bool
		clockID uint64
		addr    hostarch.Addr
		ns      int64
		// wantNS is the value served, if different from ns.
		wantNS int64
		served bool
	}{
		{
			name:    "served",
			enabled: true,
			clockID: unix.CLOCK_THREAD_CPUTIME_ID,
			addr:    userDataAddr,
			ns:      12_345_678_901,
			served:  true,
		},
		{
			name:    "updated",
			enabled: true,
			clockID: unix.CLOCK_THREAD_CPUTIME_ID,
			addr:    userDataAddr,
			ns:      23_456_789_012,
			served:  true,
		},
		{
			name:    "disabled",
			enabled: false,
			clockID: unix.CLOCK_THREAD_CPUTIME_ID,
			addr:    userDataAddr,
			ns:      34_567_890_123,
		},
		{
			name:    "other clock",
			enabled: true,
			clockID: unix.CLOCK_PROCESS_CPUTIME_ID,
			addr:    userDataAddr,
			ns:      45_678_901_234,
		},
		{
			name:    "unmapped timespec",
			enabled: true,
			clockID: unix.CLOCK_THREAD_CPUTIME_ID,
			addr:    userDataAddr + hostarch.PageSize - 8,
			ns:      56_789_012_345,
		},
		{
			name:    "reenabled",
			enabled: true,
			clockID: unix.CLOCK_THREAD_CPUTIME_ID,
			addr:    userDataAddr,
			ns:      67_890_123_456,
			served:  true,
		},
		{
			name:    "older value ignored",
			enabled: true,
			clockID: unix.CLOCK_THREAD_CPUTIME_ID,
			addr:    userDataAddr,
			ns:      1_000_000_000,
			wantNS:  67_890_123_456,
			served:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Get the application to the start of the loop, so that it uses
			// the registers set below.
			if lastSysno == unix.SYS_CLOCK_GETTIME {
				if sysno := switchToSyscall(t); sysno != unix.SYS_GETPID {
					t.Fatalf("got syscall %d, want getpid", sysno)
				}
			}
			pctx.UpdateThreadCPUClock(tc.ns)
			pctx.EnableThreadCPUClock(tc.enabled)
			ac.Regs.R12 = ^uint64(0)
			ac.Regs.R13 = uint64(tc.addr)
			ac.Regs.R14 = tc.clockID

			sysno := switchToSyscall(t)
			lastSysno = sysno
			if !tc.served {
				if sysno != unix.SYS_CLOCK_GETTIME {
					t.Fatalf("got syscall %d, want clock_gettime to reach the Sentry", sysno)
				}
				return
			}
			if sysno != unix.SYS_GETPID {
				t.Fatalf("got syscall %d, want clock_gettime to be served by the stub", sysno)
			}
			if ac.Regs.R12 != 0 {
				t.Errorf("clock_gettime returned %d, want 0", int64(ac.Regs.R12))
			}
			want := tc.ns
			if tc.wantNS != 0 {
				want = tc.wantNS
			}
			if sec, nsec := readTimespec(t); sec != want/1e9 || nsec != want%1e9 {
				t.Errorf("got timespec {%d, %d}, want {%d, %d}", sec, nsec, want/1e9, want%1e9)
			}
		})
	}
}
