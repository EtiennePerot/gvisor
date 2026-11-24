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
	"testing"

	"gvisor.dev/gvisor/pkg/cpuid"
)

// TestNativeCPUSignature checks that the CPU signature fields that
// slowDeepIdleCPU reads from the CPU directly match the host feature set, and
// that it queries only the vendor and signature leaves, once each.
func TestNativeCPUSignature(t *testing.T) {
	cpuid.Initialize()
	host := cpuid.HostFeatureSet()
	leaves := cpuidOnce{}
	native := cpuid.FeatureSet{Function: leaves}
	if got, want := slowDeepIdleCPUFeatures(native), slowDeepIdleCPUFeatures(host); got != want {
		t.Errorf("slowDeepIdleCPUFeatures() = %t querying the CPU directly, %t with the host feature set", got, want)
	}
	if got, want := native.Intel(), host.Intel(); got != want {
		t.Errorf("Intel() = %t, want %t", got, want)
	}
	if got, want := native.Family(), host.Family(); got != want {
		t.Errorf("Family() = %d, want %d", got, want)
	}
	if got, want := native.ExtendedModel(), host.ExtendedModel(); got != want {
		t.Errorf("ExtendedModel() = %d, want %d", got, want)
	}
	if got, want := native.Model(), host.Model(); got != want {
		t.Errorf("Model() = %d, want %d", got, want)
	}
	if len(leaves) != 2 {
		t.Errorf("queried CPUID leaves %v, want the vendor and signature leaves", leaves)
	}
}
