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

package sandboxsetup

import (
	"gvisor.dev/gvisor/pkg/cpuid"
)

// cpuidOnce queries each CPUID leaf from the CPU at most once.
type cpuidOnce map[cpuid.In]cpuid.Out

// Query implements cpuid.Function.Query.
func (c cpuidOnce) Query(in cpuid.In) cpuid.Out {
	out, ok := c[in]
	if !ok {
		out = (&cpuid.Native{}).Query(in)
		c[in] = out
	}
	return out
}

// slowDeepIdleCPU returns whether the host CPU's deepest idle state has a
// very high exit latency.
func slowDeepIdleCPU() bool {
	return slowDeepIdleCPUFeatures(cpuFeatures(cpuid.HostFeatureSet()))
}

// cpuFeatures returns host, the host feature set, if the cpuid package is
// initialized. Otherwise, it returns a feature set that queries the CPU
// directly, since initializing the package costs much more.
func cpuFeatures(host cpuid.FeatureSet) cpuid.FeatureSet {
	if host.Function != nil {
		return host
	}
	return cpuid.FeatureSet{Function: cpuidOnce{}}
}

// slowDeepIdleCPUFeatures returns whether the deepest idle state of the CPU
// that fs describes has a very high exit latency.
func slowDeepIdleCPUFeatures(fs cpuid.FeatureSet) bool {
	if !fs.Intel() || fs.Family() != 6 {
		return false
	}
	// Recent Intel Xeon server CPUs take ~150-230us to wake a CPU from C6, an
	// order of magnitude more than other CPUs (e.g. AMD EPYC's deepest state
	// measures ~5-15us). Advertised sysfs exit latencies do not distinguish
	// them; only measurement does. To decide whether a new CPU model belongs
	// here, run tools/cstate_wake_probe on an otherwise idle machine.
	switch uint16(fs.ExtendedModel())<<4 | uint16(fs.Model()) {
	case 0x8f, // Sapphire Rapids
		0xcf, // Emerald Rapids
		0xad, // Granite Rapids
		0xae: // Granite Rapids D
		return true
	}
	return false
}
