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

package stubfilter

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

func setSysmsgThreadArchVars(vars precompiledseccomp.Values, stubStart uint64) {
	vars.SetUint64(stubStartVar, stubStart)
}

func stubProcessArchRules() []seccomp.RuleSet {
	return []seccomp.RuleSet{
		{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_ARCH_PRCTL: seccomp.Or{
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_SET_FS)},
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_GET_FS)},
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_SET_GS)},
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_GET_GS)},
				},
			}),
			Action: seccomp.Allow,
		},
	}
}

func sysmsgThreadArchRules(vars precompiledseccomp.Values) []seccomp.RuleSet {
	stubStart := vars.GetUint64(stubStartVar)
	return []seccomp.RuleSet{
		{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_ARCH_PRCTL: seccomp.Or{
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_SET_FS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_GET_FS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_SET_GS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_GET_GS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
				},
			}),
			Action: seccomp.Allow,
		},
	}
}
