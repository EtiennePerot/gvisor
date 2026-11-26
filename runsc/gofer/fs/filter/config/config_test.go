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

package config

import (
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

// TestOptionsConfigKey verifies the behavior of `Options.ConfigKey`.
func TestOptionsConfigKey(t *testing.T) {
	// mutateFn mutates the value of a specific Options field.
	type mutateFn func(opt *Options)

	var defaultOpt Options

	// Map of `Options` struct field names mapped to a function to mutate them.
	// This should only contain fields which influence the configuration.
	// Calling the mutation function of these should change the value of
	// `Options.ConfigKey`.
	configFields := map[string]mutateFn{
		"UDSOpenEnabled":   func(opt *Options) { opt.UDSOpenEnabled = !opt.UDSOpenEnabled },
		"UDSCreateEnabled": func(opt *Options) { opt.UDSCreateEnabled = !opt.UDSCreateEnabled },
		"ProfileEnabled":   func(opt *Options) { opt.ProfileEnabled = !opt.ProfileEnabled },
		"HostFS":           func(opt *Options) { opt.HostFS = (opt.HostFS + 1) % (HostFSReadWrite + 1) },
		"CgoEnabled":       func(opt *Options) { opt.CgoEnabled = !opt.CgoEnabled },
		"ExtraRules": func(opt *Options) {
			if len(opt.ExtraRules) == 0 {
				opt.ExtraRules = []seccomp.SyscallRules{
					seccomp.NewSyscallRules().Add(uintptr(123456), seccomp.MatchAll{}),
				}
			} else {
				opt.ExtraRules = nil
			}
		},
		"VendorSyscalls": func(opt *Options) {
			if len(opt.VendorSyscalls) == 0 {
				opt.VendorSyscalls = precompiledseccomp.VarSyscallNumbers{"test": 1000}
			} else {
				opt.VendorSyscalls = nil
			}
		},
	}

	varFields := map[string]mutateFn{
		"ProcSelfFD": func(opt *Options) { opt.ProcSelfFD++ },
	}

	t.Run("fields are exhaustive", func(t *testing.T) {
		for i := 0; i < reflect.ValueOf(defaultOpt).NumField(); i++ {
			f := reflect.TypeOf(defaultOpt).Field(i)
			_, isConfig := configFields[f.Name]
			_, isVar := varFields[f.Name]
			if !isConfig && !isVar {
				t.Fatalf("field `Options.%s` is not known to TestOptionsConfigKey; please add it", f.Name)
			}
		}
	})

	t.Run("mutating config fields causes ConfigKey to change", func(t *testing.T) {
		opt := defaultOpt // Make a copy, as we're about to mutate it.
		key := opt.ConfigKey()
		for name, mutateFn := range configFields {
			mutateFn(&opt)
			newKey := opt.ConfigKey()
			if key == newKey {
				t.Fatalf("mutating config field %q did not cause the ConfigKey to change: %q", name, key)
			}
			key = newKey
		}
	})

	t.Run("mutating var fields does not cause ConfigKey to change", func(t *testing.T) {
		opt := defaultOpt
		key := opt.ConfigKey()
		for name, mutateFn := range varFields {
			mutateFn(&opt)
			if newKey := opt.ConfigKey(); key != newKey {
				t.Fatalf("mutating var field %q changed ConfigKey from %q to %q", name, key, newKey)
			}
		}
	})
}

// TestPrecompiledPrograms verifies that all option variants precompile
// successfully, that their names are unique, and that each of them renders
// with the variable values that this process would use at runtime.
func TestPrecompiledPrograms(t *testing.T) {
	programs, err := PrecompiledPrograms()
	if err != nil {
		t.Fatalf("PrecompiledPrograms() failed: %v", err)
	}
	byName := make(map[string]int, len(programs))
	for i, program := range programs {
		if prev, dup := byName[program.Name]; dup {
			t.Errorf("programs %d and %d have the same name: %q", prev, i, program.Name)
		}
		byName[program.Name] = i
	}
	for _, opt := range optionsToPrecompile() {
		i, found := byName[opt.ConfigKey()]
		if !found {
			t.Errorf("no precompiled program for options %v", opt.ConfigKey())
			continue
		}
		for _, procSelfFD := range []uint32{0, 42} {
			opt.ProcSelfFD = procSelfFD
			rendered, err := programs[i].RenderInstructions(opt.Vars())
			if err != nil {
				t.Errorf("cannot render precompiled program for options %v (ProcSelfFD=%d): %v", opt.ConfigKey(), procSelfFD, err)
				continue
			}
			rules, denyRules := Rules(opt)
			program := seccomp.Program{
				RuleSets: []seccomp.RuleSet{
					{Rules: denyRules},
					{Rules: rules, Action: seccomp.Allow},
				},
				Options: seccomp.ProgramOptions{DefaultAction: seccomp.KillProcess},
			}
			want, _, err := program.Build()
			if err != nil {
				t.Errorf("cannot build program for options %v (ProcSelfFD=%d): %v", opt.ConfigKey(), procSelfFD, err)
				continue
			}
			if !reflect.DeepEqual(rendered, want) {
				t.Errorf("rendered precompiled program for options %v (ProcSelfFD=%d) differs from Rules(opt)", opt.ConfigKey(), procSelfFD)
			}
		}
	}
}

// TestPrecompiledProgramsDeterministic verifies that compiling programs
// concurrently produces the same output as compiling them one at a time.
func TestPrecompiledProgramsDeterministic(t *testing.T) {
	// Make sure that compilations run in parallel even with few CPUs.
	const minProcs = 8
	if runtime.GOMAXPROCS(0) < minProcs {
		defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(minProcs))
	}
	serial, err := precompiledPrograms(1)
	if err != nil {
		t.Fatalf("precompiledPrograms(1) failed: %v", err)
	}
	concurrent, err := PrecompiledPrograms()
	if err != nil {
		t.Fatalf("PrecompiledPrograms() failed: %v", err)
	}
	if len(serial) != len(concurrent) {
		t.Fatalf("got %d programs when compiling concurrently, want %d", len(concurrent), len(serial))
	}
	for i := range serial {
		if !reflect.DeepEqual(serial[i], concurrent[i]) {
			t.Errorf("program %d (%q) differs between serial and concurrent compilation (concurrent name: %q)", i, serial[i].Name, concurrent[i].Name)
		}
	}
}

func compileFilter(t *testing.T, opt Options) bpf.Program {
	t.Helper()
	rules, denyRules := Rules(opt)
	program := seccomp.Program{
		RuleSets: []seccomp.RuleSet{
			{Rules: denyRules},
			{Rules: rules, Action: seccomp.Allow},
		},
		Options: seccomp.ProgramOptions{DefaultAction: seccomp.KillProcess},
	}
	insns, _, err := program.Build()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := bpf.Compile(insns, false /* optimize */)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func filterAllows(t *testing.T, compiled bpf.Program, sysno uintptr, args [6]uint64) bool {
	t.Helper()
	data := linux.SeccompData{Nr: int32(sysno), Arch: seccomp.LINUX_AUDIT_ARCH, Args: args}
	got, err := bpf.Exec[bpf.NativeEndian](compiled, seccomp.DataAsBPFInput(&data, make([]byte, data.SizeBytes())))
	if err != nil {
		t.Fatalf("syscall %d with args %#x: %v", sysno, args, err)
	}
	switch got {
	case uint32(linux.SECCOMP_RET_ALLOW):
		return true
	case uint32(linux.SECCOMP_RET_KILL_PROCESS):
		return false
	default:
		t.Fatalf("syscall %d with args %#x: unexpected action %#x", sysno, args, got)
		return false
	}
}

func TestRPCSyscalls(t *testing.T) {
	const (
		fd         = 10
		procSelfFD = 42
		ptr        = 0x1000
	)
	atFDCWD32 := int32(linux.AT_FDCWD)
	atFDCWD64 := int64(linux.AT_FDCWD)
	negOne := ^uint64(0)

	var cases []Options
	for _, hostFS := range []HostFSAccess{HostFSNone, HostFSReadWrite} {
		for _, udsOpen := range []bool{false, true} {
			for _, udsCreate := range []bool{false, true} {
				cases = append(cases, Options{
					HostFS:           hostFS,
					ProcSelfFD:       procSelfFD,
					UDSOpenEnabled:   udsOpen,
					UDSCreateEnabled: udsCreate,
				})
			}
		}
	}
	cases = append(cases,
		Options{HostFS: HostFSNone, ProcSelfFD: procSelfFD, ProfileEnabled: true},
		Options{HostFS: HostFSNone, ProcSelfFD: procSelfFD, CgoEnabled: true},
	)

	for _, opt := range cases {
		t.Run(opt.ConfigKey(), func(t *testing.T) {
			fileRPCs := opt.HostFS != HostFSNone
			bindRPC := opt.UDSCreateEnabled
			compiled := compileFilter(t, opt)
			for _, sc := range []struct {
				name  string
				sysno uintptr
				args  [6]uint64
				want  bool
			}{
				{"openat", unix.SYS_OPENAT, [6]uint64{fd, ptr, unix.O_RDONLY | unix.O_NOFOLLOW}, true},
				{"connect", unix.SYS_CONNECT, [6]uint64{fd, ptr, 16}, opt.UDSOpenEnabled},
				{"bind", unix.SYS_BIND, [6]uint64{fd, ptr, 16}, bindRPC},

				{"fchmod", unix.SYS_FCHMOD, [6]uint64{fd, 0o644}, fileRPCs || bindRPC},
				{"fchmod AT_FDCWD 32-bit", unix.SYS_FCHMOD, [6]uint64{uint64(uint32(atFDCWD32)), 0o644}, false},
				{"fchmod AT_FDCWD 64-bit", unix.SYS_FCHMOD, [6]uint64{uint64(atFDCWD64), 0o644}, false},
				{"fchmod negative FD", unix.SYS_FCHMOD, [6]uint64{negOne, 0o644}, false},
				{"fchmod high FD bits", unix.SYS_FCHMOD, [6]uint64{(1 << 32) | fd, 0o644}, false},

				{"fchownat", unix.SYS_FCHOWNAT, [6]uint64{fd, ptr, 1, 1, unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW}, fileRPCs || bindRPC},
				{"fchownat unchanged uid/gid", unix.SYS_FCHOWNAT, [6]uint64{fd, ptr, negOne, negOne, unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW}, fileRPCs || bindRPC},
				{"fchownat AT_FDCWD 32-bit", unix.SYS_FCHOWNAT, [6]uint64{uint64(uint32(atFDCWD32)), ptr, 1, 1, unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW}, false},
				{"fchownat AT_FDCWD 64-bit", unix.SYS_FCHOWNAT, [6]uint64{uint64(atFDCWD64), ptr, 1, 1, unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW}, false},
				{"fchownat negative FD", unix.SYS_FCHOWNAT, [6]uint64{negOne, ptr, 1, 1, unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW}, false},
				{"fchownat high FD bits", unix.SYS_FCHOWNAT, [6]uint64{(1 << 32) | fd, ptr, 1, 1, unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW}, false},
				{"fchownat flags=0", unix.SYS_FCHOWNAT, [6]uint64{fd, ptr, 1, 1, 0}, false},
				{"fchownat missing AT_SYMLINK_NOFOLLOW", unix.SYS_FCHOWNAT, [6]uint64{fd, ptr, 1, 1, unix.AT_EMPTY_PATH}, false},
				{"fchownat missing AT_EMPTY_PATH", unix.SYS_FCHOWNAT, [6]uint64{fd, ptr, 1, 1, unix.AT_SYMLINK_NOFOLLOW}, false},
				{"fchownat extra flag bit", unix.SYS_FCHOWNAT, [6]uint64{fd, ptr, 1, 1, unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT}, false},
				{"fchownat high flag bits", unix.SYS_FCHOWNAT, [6]uint64{fd, ptr, 1, 1, (1 << 32) | unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW}, false},

				{"fchmodat", unix.SYS_FCHMODAT, [6]uint64{procSelfFD, ptr, 0o644}, fileRPCs},
				{"fchmodat other FD", unix.SYS_FCHMODAT, [6]uint64{fd, ptr, 0o644}, false},
				{"fchmodat high FD bits", unix.SYS_FCHMODAT, [6]uint64{(1 << 32) | procSelfFD, ptr, 0o644}, false},
				{"fchmodat AT_FDCWD 32-bit", unix.SYS_FCHMODAT, [6]uint64{uint64(uint32(atFDCWD32)), ptr, 0o644}, false},
				{"fchmodat AT_FDCWD 64-bit", unix.SYS_FCHMODAT, [6]uint64{uint64(atFDCWD64), ptr, 0o644}, false},
				{"fchmodat negative FD", unix.SYS_FCHMODAT, [6]uint64{negOne, ptr, 0o644}, false},

				{"openat2", unix.SYS_OPENAT2, [6]uint64{uint64(atFDCWD64), ptr, ptr, unix.SizeofOpenHow}, fileRPCs},
				{"openat2 positive FD", unix.SYS_OPENAT2, [6]uint64{fd, ptr, ptr, unix.SizeofOpenHow}, false},
				{"openat2 AT_FDCWD 32-bit", unix.SYS_OPENAT2, [6]uint64{uint64(uint32(atFDCWD32)), ptr, ptr, unix.SizeofOpenHow}, false},
				{"openat2 negative FD", unix.SYS_OPENAT2, [6]uint64{negOne, ptr, ptr, unix.SizeofOpenHow}, false},
				{"openat2 size=0", unix.SYS_OPENAT2, [6]uint64{uint64(atFDCWD64), ptr, ptr, 0}, false},
				{"openat2 oversized open_how", unix.SYS_OPENAT2, [6]uint64{uint64(atFDCWD64), ptr, ptr, unix.SizeofOpenHow + 8}, false},
				{"openat2 high size bits", unix.SYS_OPENAT2, [6]uint64{uint64(atFDCWD64), ptr, ptr, (1 << 32) | unix.SizeofOpenHow}, false},

				{"unlinkat file", unix.SYS_UNLINKAT, [6]uint64{fd, ptr, 0}, fileRPCs || bindRPC},
				{"unlinkat AT_FDCWD 32-bit", unix.SYS_UNLINKAT, [6]uint64{uint64(uint32(atFDCWD32)), ptr, 0}, fileRPCs},
				{"unlinkat AT_FDCWD 64-bit", unix.SYS_UNLINKAT, [6]uint64{uint64(atFDCWD64), ptr, 0}, fileRPCs},
				{"unlinkat negative FD", unix.SYS_UNLINKAT, [6]uint64{negOne, ptr, 0}, fileRPCs},
				{"unlinkat high FD bits", unix.SYS_UNLINKAT, [6]uint64{(1 << 32) | fd, ptr, 0}, fileRPCs},
				{"unlinkat directory", unix.SYS_UNLINKAT, [6]uint64{fd, ptr, unix.AT_REMOVEDIR}, fileRPCs},
				{"unlinkat unknown flag", unix.SYS_UNLINKAT, [6]uint64{fd, ptr, 1}, fileRPCs},
				{"unlinkat high flag bits", unix.SYS_UNLINKAT, [6]uint64{fd, ptr, 1 << 32}, fileRPCs},
				{"fchmodat2", unix.SYS_FCHMODAT2, [6]uint64{fd, ptr, 0o644, 0}, false},
				{"fchown", unix.SYS_FCHOWN, [6]uint64{fd, 1, 1}, false},
			} {
				if got := filterAllows(t, compiled, sc.sysno, sc.args); got != sc.want {
					t.Errorf("%s: allowed=%t, want %t", sc.name, got, sc.want)
				}
			}
		})
	}
}

func TestMknodat(t *testing.T) {
	atFDCWD32 := int32(linux.AT_FDCWD)
	atFDCWD64 := int64(linux.AT_FDCWD)
	for _, hostFS := range []HostFSAccess{HostFSNone, HostFSReadWrite} {
		compiled := compileFilter(t, Options{HostFS: hostFS})
		lisafsEnabled := hostFS == HostFSReadWrite
		for _, tc := range []struct {
			name    string
			args    [6]uint64
			allowed bool
		}{
			{"regular file", [6]uint64{10, 0x1000, unix.S_IFREG | 0o644, 0}, lisafsEnabled},
			{"regular file setuid sticky", [6]uint64{0, 0x1000, unix.S_IFREG | 0o7777, 0}, lisafsEnabled},
			{"whiteout char device", [6]uint64{10, 0x1000, unix.S_IFCHR, 0}, lisafsEnabled},
			{"whiteout char device with perms", [6]uint64{10, 0x1000, unix.S_IFCHR | 0o644, 0}, lisafsEnabled},
			{"non-whiteout char device", [6]uint64{10, 0x1000, unix.S_IFCHR | 0o666, 0x0103}, false},
			{"regular file nonzero dev", [6]uint64{10, 0x1000, unix.S_IFREG | 0o644, 1}, false},
			{"dev high bits set", [6]uint64{10, 0x1000, unix.S_IFCHR, 1 << 32}, false},
			{"zero file type", [6]uint64{10, 0x1000, 0o644, 0}, false},
			{"fifo", [6]uint64{10, 0x1000, unix.S_IFIFO | 0o644, 0}, false},
			{"socket", [6]uint64{10, 0x1000, unix.S_IFSOCK | 0o644, 0}, false},
			{"block device", [6]uint64{10, 0x1000, unix.S_IFBLK | 0o644, 0}, false},
			{"directory", [6]uint64{10, 0x1000, unix.S_IFDIR | 0o755, 0}, false},
			{"symlink", [6]uint64{10, 0x1000, unix.S_IFLNK | 0o777, 0}, false},
			{"AT_FDCWD 32-bit", [6]uint64{uint64(uint32(atFDCWD32)), 0x1000, unix.S_IFREG | 0o644, 0}, false},
			{"AT_FDCWD 64-bit", [6]uint64{uint64(atFDCWD64), 0x1000, unix.S_IFREG | 0o644, 0}, false},
			{"negative FD", [6]uint64{^uint64(0), 0x1000, unix.S_IFREG | 0o644, 0}, false},
		} {
			if allowed := filterAllows(t, compiled, unix.SYS_MKNODAT, tc.args); allowed != tc.allowed {
				t.Errorf("HostFS=%v %s: allowed=%t, want %t", hostFS, tc.name, allowed, tc.allowed)
			}
		}
	}
}

func TestHostFSAccess(t *testing.T) {
	for _, tc := range []struct {
		level HostFSAccess
		want  string
	}{
		{HostFSNone, "none"},
		{HostFSReadWrite, "readwrite"},
		{HostFSAccess(-1), "HostFSAccess(-1)"},
		{HostFSReadWrite + 1, "HostFSAccess(2)"},
	} {
		if got := tc.level.String(); got != tc.want {
			t.Errorf("HostFSAccess(%d).String() = %q, want %q", tc.level, got, tc.want)
		}
	}

	for _, invalid := range []HostFSAccess{-1, HostFSReadWrite + 1} {
		opt := Options{HostFS: invalid}
		for _, tc := range []struct {
			name string
			fn   func()
		}{
			{"Vars", func() { _ = opt.Vars() }},
			{"Rules", func() { _, _ = opt.Rules() }},
		} {
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Options{HostFS: %d}.%s() did not panic", invalid, tc.name)
					}
				}()
				tc.fn()
			}()
		}
	}
}
