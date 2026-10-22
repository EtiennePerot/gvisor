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

package sandbox

import (
	"fmt"
	"maps"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
)

// CPULimits are the CPU limits of the sandbox cgroup.
type CPULimits struct {
	// App applies while the application runs.
	App specs.LinuxCPU `json:"app"`

	// Lifecycle applies for sandbox lifecycle operations.
	Lifecycle specs.LinuxCPU `json:"lifecycle"`
}

// NewCPULimits returns the CPU limits for `res` under `policy`, or nil if the
// OCI spec limit applies throughout.
func NewCPULimits(policy config.SandboxLifecycleCPUPolicy, res *specs.LinuxResources) *CPULimits {
	if !policy.Enabled() || res == nil {
		return nil
	}
	var quota int64
	period := uint64(cgroup.DefaultCPUPeriod)
	if res.CPU != nil {
		if res.CPU.Quota != nil {
			quota = *res.CPU.Quota
		}
		if res.CPU.Period != nil && *res.CPU.Period != 0 {
			period = *res.CPU.Period
		}
	}
	if cpuMax, ok := res.Unified["cpu.max"]; ok {
		unifiedQuota, unifiedPeriod, err := cgroup.ParseCPUMax(cpuMax)
		if err != nil {
			log.Warningf("Not applying --sandbox-lifecycle-cpu-policy=%v: cannot parse unified cpu.max: %v", policy, err)
			return nil
		}
		quota, period = unifiedQuota, uint64(unifiedPeriod)
	}
	if quota <= 0 {
		return nil
	}
	lifecycleQuota := policy.Quota(quota, period)
	if lifecycleQuota == quota {
		return nil
	}
	return &CPULimits{
		App:       specs.LinuxCPU{Quota: &quota, Period: &period},
		Lifecycle: specs.LinuxCPU{Quota: &lifecycleQuota, Period: &period},
	}
}

// LifecycleResources returns a copy of `res` with the lifecycle CPU limit.
func (l *CPULimits) LifecycleResources(res *specs.LinuxResources) *specs.LinuxResources {
	var cpu specs.LinuxCPU
	if res.CPU != nil {
		cpu = *res.CPU
	}
	cpu.Quota, cpu.Period = l.Lifecycle.Quota, l.Lifecycle.Period
	lifecycleRes := *res
	lifecycleRes.CPU = &cpu
	if _, ok := res.Unified["cpu.max"]; ok {
		lifecycleRes.Unified = maps.Clone(res.Unified)
		delete(lifecycleRes.Unified, "cpu.max")
	}
	return &lifecycleRes
}

// limitCPUForApp applies the application CPU limit to the sandbox cgroup.
func (s *Sandbox) limitCPUForApp() error {
	if s.CPULimits == nil {
		return nil
	}
	if err := s.CgroupJSON.Cgroup.Update(&specs.LinuxResources{CPU: &s.CPULimits.App}); err != nil {
		return fmt.Errorf("cannot apply application CPU limit: %w", err)
	}
	log.Infof("[Lifecycle CPU] Applied application CPU limit: quota=%d period=%d", *s.CPULimits.App.Quota, *s.CPULimits.App.Period)
	return nil
}

// limitCPUForLifecycle applies the lifecycle CPU limit to the sandbox cgroup.
func (s *Sandbox) limitCPUForLifecycle() error {
	if s.CPULimits == nil {
		return nil
	}
	if err := s.CgroupJSON.Cgroup.Update(&specs.LinuxResources{CPU: &s.CPULimits.Lifecycle}); err != nil {
		return fmt.Errorf("cannot apply lifecycle CPU limit: %w", err)
	}
	log.Infof("[Lifecycle CPU] Applied lifecycle CPU limit: quota=%d period=%d", *s.CPULimits.Lifecycle.Quota, *s.CPULimits.Lifecycle.Period)
	return nil
}
