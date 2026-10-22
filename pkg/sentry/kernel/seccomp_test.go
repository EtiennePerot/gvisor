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

package kernel

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
)

const (
	testSysno = 228 // Arbitrary.
	testArch  = linux.AUDIT_ARCH_X86_64

	// Offsets in linux.SeccompData.
	seccompDataNr   = 0
	seccompDataIP   = 8
	seccompDataArg0 = 16
)

func mustCompile(t *testing.T, insns ...bpf.Instruction) bpf.Program {
	t.Helper()
	p, err := bpf.Compile(insns, true /* optimize */)
	if err != nil {
		t.Fatalf("bpf.Compile failed: %v", err)
	}
	return p
}

// filterFor returns a filter that returns action for testSysno, and allows all
// other system calls.
func filterFor(t *testing.T, action linux.BPFAction) bpf.Program {
	return mustCompile(t,
		bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataNr),
		bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, testSysno, 0, 1),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(action)),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)),
	)
}

func TestSeccompAlwaysAllows(t *testing.T) {
	allowAll := mustCompile(t, bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)))
	// Allow testSysno only if its first argument is 3.
	argDependent := mustCompile(t,
		bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataNr),
		bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, testSysno, 0, 3),
		bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataArg0),
		bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, 3, 0, 1),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ERRNO|1)),
	)
	// Deny everything from a given (low 32 bits of the) instruction pointer.
	ipDependent := mustCompile(t,
		bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataIP),
		bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, 0x1000, 0, 1),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ERRNO|1)),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)),
	)

	type testCase struct {
		name    string
		filters []bpf.Program
		arch    uint32
		want    bool
	}
	tests := []testCase{
		{name: "allow all", filters: []bpf.Program{allowAll}, arch: testArch, want: true},
		{name: "allow all twice", filters: []bpf.Program{allowAll, allowAll}, arch: testArch, want: true},
		{name: "other syscall denied", filters: []bpf.Program{mustCompile(t,
			bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataNr),
			bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, testSysno+1, 0, 1),
			bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_KILL_PROCESS)),
			bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)),
		)}, arch: testArch, want: true},
		{name: "other arch", filters: []bpf.Program{allowAll}, arch: linux.AUDIT_ARCH_AARCH64, want: false},
		{name: "argument dependent", filters: []bpf.Program{argDependent}, arch: testArch, want: false},
		{name: "instruction pointer dependent", filters: []bpf.Program{ipDependent}, arch: testArch, want: false},
	}
	for _, action := range []linux.BPFAction{
		linux.SECCOMP_RET_KILL_PROCESS,
		linux.SECCOMP_RET_KILL_THREAD,
		linux.SECCOMP_RET_TRAP,
		linux.SECCOMP_RET_ERRNO | 1,
		linux.SECCOMP_RET_TRACE,
		linux.SECCOMP_RET_USER_NOTIF,
		linux.SECCOMP_RET_LOG,
	} {
		tests = append(tests,
			testCase{name: fmt.Sprintf("action %#x", uint32(action)), filters: []bpf.Program{filterFor(t, action)}, arch: testArch, want: false},
			testCase{name: fmt.Sprintf("action %#x after allow all", uint32(action)), filters: []bpf.Program{allowAll, filterFor(t, action)}, arch: testArch, want: false},
			testCase{name: fmt.Sprintf("action %#x before allow all", uint32(action)), filters: []bpf.Program{filterFor(t, action), allowAll}, arch: testArch, want: false},
		)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task := &Task{}
			task.image.st = &SyscallTable{AuditNumber: testArch}
			ts := &taskSeccomp{filters: test.filters}
			ts.populateCache(task)
			if got := ts.alwaysAllows(test.arch, testSysno); got != test.want {
				t.Errorf("alwaysAllows(%#x, %d) = %t, want %t", test.arch, testSysno, got, test.want)
			}
		})
	}
}
