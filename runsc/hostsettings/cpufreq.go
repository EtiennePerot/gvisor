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

package hostsettings

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gvisor.dev/gvisor/runsc/config"
)

const (
	// cpufreqDir is where the kernel exposes CPU frequency scaling policies.
	// It only has policies on hosts where the OS controls CPU frequency,
	// typically bare-metal machines. Most cloud VMs (including GCE VMs, and
	// thus GKE nodes) have no cpufreq driver, so this setting is a no-op there.
	cpufreqDir = "/sys/devices/system/cpu/cpufreq"

	// performanceGovernor is the recommended governor.
	performanceGovernor = "performance"

	// userspaceGovernor runs CPUs at a frequency chosen by the administrator.
	// Policies using it are left alone.
	userspaceGovernor = "userspace"
)

// cpuGovernorSetting checks that cpufreq policies use the performance
// governor.
//
// Starting or restoring a sandbox is a burst of short-lived, mostly
// single-threaded work spread over several processes (runsc, gofer, sandbox)
// that land on whatever CPUs are idle. Demand-driven governors (e.g.
// intel_pstate "powersave", schedutil, ondemand) keep idle CPUs at a low
// frequency, and the burst is mostly over before they ramp up.
//
// Host settings are checked on every sandbox start and restore, and reading
// every policy's governor costs tens of microseconds per CPU, so only CPU 0's
// policy is checked. Governors are almost always set uniformly (by the kernel
// default or by host tooling setting all policies at once). When CPU 0's
// policy is not optimal, Apply changes every policy that is neither
// "performance" nor "userspace".
type cpuGovernorSetting struct {
	// dir is the cpufreq sysfs directory; overridden by tests.
	dir string
}

func (s cpuGovernorSetting) governorPath(policy string) string {
	return filepath.Join(s.dir, policy, "scaling_governor")
}

// Name implements Setting.Name.
func (s cpuGovernorSetting) Name() string {
	return s.governorPath("policy*")
}

// Delta implements Setting.Delta.
func (s cpuGovernorSetting) Delta(conf *config.Config) (*Delta, error) {
	probe := s.governorPath("policy0")
	b, err := os.ReadFile(probe)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cpufreq driver.
		}
		return nil, fmt.Errorf("cannot read %q: %w", probe, err)
	}
	current := strings.TrimSpace(string(b))
	if current == performanceGovernor || current == userspaceGovernor {
		return nil, nil
	}
	return &Delta{
		Name:      s.Name(),
		FromValue: current,
		ToValue:   performanceGovernor,
		Purpose:   "demand-driven CPU frequency governors run the short bursts of work in sandbox startup and restore at low frequency; the performance governor avoids this at the cost of higher host power use",
		Apply:     s.apply,
	}, nil
}

// apply sets the performance governor on every policy that does not use the
// performance or userspace governor.
func (s cpuGovernorSetting) apply() error {
	paths, err := filepath.Glob(s.governorPath("policy*"))
	if err != nil {
		return err
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("cannot read %q: %w", p, err)
		}
		switch strings.TrimSpace(string(b)) {
		case performanceGovernor, userspaceGovernor:
			continue
		}
		if err := os.WriteFile(p, []byte(performanceGovernor), 0644); err != nil {
			return fmt.Errorf("cannot write %q: %w", p, err)
		}
		// Double-check that the governor has been changed.
		b, err = os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("cannot re-read %q after writing: %w", p, err)
		}
		if got := strings.TrimSpace(string(b)); got != performanceGovernor {
			return fmt.Errorf("writing to %q did not change the observed value: wrote %q but read back %q", p, performanceGovernor, got)
		}
	}
	return nil
}
