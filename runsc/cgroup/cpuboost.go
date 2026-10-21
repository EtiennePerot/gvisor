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

package cgroup

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	cpuWeightCgroup = "cpu.weight"
	maxCPUWeight    = 10000

	// cpuBoostXattr is the extended attribute of a boosted cgroup's directory
	// that records the boost. Recording it with the cgroup, rather than with
	// the sandbox, lets any later runsc process undo it, including one that
	// creates another sandbox in the same cgroup after the sandbox that
	// boosted it was abandoned.
	cpuBoostXattr = "user.gvisor.cpu_boost"
)

// CPUBoost records a temporary increase of a cgroup's CPU limit (cpu.max) and
// CPU weight (cpu.weight).
type CPUBoost struct {
	// Dir is the cgroup directory.
	Dir string `json:"-"`
	// Max and BoostedMax are the cpu.max values before and during the boost.
	Max        string `json:"max"`
	BoostedMax string `json:"boostedMax"`
	// Weight and BoostedWeight are the cpu.weight values before and during
	// the boost. Both are empty if the weight isn't changed.
	Weight        string `json:"weight,omitempty"`
	BoostedWeight string `json:"boostedWeight,omitempty"`
}

// BoostedCPUQuota returns the CPU quota to use, for the given period, instead
// of quota while the CPU limit is raised to at least minCPUs. It returns
// quota itself if the limit should not be raised: quota is unlimited (<= 0)
// or already at least minCPUs.
func BoostedCPUQuota(quota, period int64, minCPUs float64) int64 {
	if quota <= 0 || period <= 0 {
		return quota
	}
	return max(quota, int64(math.Ceil(minCPUs*float64(period))))
}

// boostableDir returns the directory of cg if runsc may boost its CPU limit,
// i.e. cg is a cgroupfs-managed cgroup v2. With cgroup v1 or the systemd
// driver, runsc doesn't own the limit.
func boostableDir(cg Cgroup) string {
	if v2, ok := cg.(*cgroupV2); ok {
		return v2.MakePath("")
	}
	return ""
}

// BoostCPU raises the CPU limit of cg to at least minCPUs CPUs if it is
// lower, and multiplies its CPU weight by the same factor (up to the maximum
// weight). It records the boost on the cgroup before changing anything. If cg
// is already boosted, it changes nothing and returns the recorded boost. It
// returns nil if cg isn't boosted and doesn't need to be: runsc doesn't
// manage its limit (see boostableDir), it has no CPU limit, or the limit is
// at least minCPUs.
func BoostCPU(cg Cgroup, minCPUs float64) (*CPUBoost, error) {
	dir := boostableDir(cg)
	if dir == "" || minCPUs <= 0 {
		return nil, nil
	}
	if b, err := loadCPUBoost(dir); err != nil || b != nil {
		return b, err
	}
	b, err := planCPUBoost(dir, minCPUs)
	if err != nil || b == nil {
		return nil, err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if err := unix.Setxattr(dir, cpuBoostXattr, data, unix.XATTR_CREATE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			// Raced with another process boosting the cgroup.
			return loadCPUBoost(dir)
		}
		return nil, fmt.Errorf("recording CPU boost of %q: %w", dir, err)
	}
	if err := setValue(dir, cpuLimitCgroup, b.BoostedMax); err != nil {
		_ = unix.Removexattr(dir, cpuBoostXattr)
		return nil, err
	}
	if b.Weight != "" {
		if err := setValue(dir, cpuWeightCgroup, b.BoostedWeight); err != nil {
			// The weight only matters under contention. Restore leaves it
			// alone, since it doesn't have the boosted value.
			log.Warningf("Setting %s in %q: %v", cpuWeightCgroup, dir, err)
		}
	}
	log.Infof("CPU limit of %q raised from %q to %q, weight from %q to %q", dir, b.Max, b.BoostedMax, b.Weight, b.BoostedWeight)
	return b, nil
}

// WouldBoostCPU returns true if BoostCPU(cg, minCPUs) would return a boost.
func WouldBoostCPU(cg Cgroup, minCPUs float64) bool {
	dir := boostableDir(cg)
	if dir == "" || minCPUs <= 0 {
		return false
	}
	if b, err := loadCPUBoost(dir); err != nil || b != nil {
		return err == nil
	}
	b, err := planCPUBoost(dir, minCPUs)
	return err == nil && b != nil
}

// LoadCPUBoost returns the boost recorded on cg, or nil if cg isn't boosted.
func LoadCPUBoost(cg Cgroup) (*CPUBoost, error) {
	dir := boostableDir(cg)
	if dir == "" {
		return nil, nil
	}
	return loadCPUBoost(dir)
}

func loadCPUBoost(dir string) (*CPUBoost, error) {
	buf := make([]byte, 256)
	n, err := unix.Getxattr(dir, cpuBoostXattr, buf)
	if err != nil {
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading CPU boost of %q: %w", dir, err)
	}
	b := &CPUBoost{Dir: dir}
	if err := json.Unmarshal(buf[:n], b); err != nil {
		return nil, fmt.Errorf("parsing CPU boost of %q: %w", dir, err)
	}
	return b, nil
}

// planCPUBoost returns the boost that BoostCPU would apply to the cgroup in
// dir, or nil.
func planCPUBoost(dir string, minCPUs float64) (*CPUBoost, error) {
	cpuMax, err := getValue(dir, cpuLimitCgroup)
	if err != nil {
		if os.IsNotExist(err) {
			// No cpu controller.
			return nil, nil
		}
		return nil, err
	}
	quota, period, err := parseCPUQuotaAndPeriod(cpuMax)
	if err != nil {
		return nil, err
	}
	boosted := BoostedCPUQuota(quota, period, minCPUs)
	if boosted == quota {
		return nil, nil
	}
	b := &CPUBoost{
		Dir:        dir,
		Max:        strings.TrimSpace(cpuMax),
		BoostedMax: fmt.Sprintf("%d %d", boosted, period),
	}
	if val, err := getValue(dir, cpuWeightCgroup); err == nil {
		if weight, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64); err == nil {
			if w := min(maxCPUWeight, int64(math.Round(float64(weight)*float64(boosted)/float64(quota)))); w > weight {
				b.Weight, b.BoostedWeight = strconv.FormatInt(weight, 10), strconv.FormatInt(w, 10)
			}
		}
	}
	return b, nil
}

// Restore undoes the boost and removes its record. It leaves each file alone
// if its value changed since the boost (e.g. if the CPU limit was updated in
// between), and ignores a cgroup that no longer exists.
func (b *CPUBoost) Restore() error {
	if err := restoreValue(b.Dir, cpuLimitCgroup, b.BoostedMax, b.Max); err != nil {
		return err
	}
	if b.Weight != "" {
		if err := restoreValue(b.Dir, cpuWeightCgroup, b.BoostedWeight, b.Weight); err != nil {
			return err
		}
	}
	if err := unix.Removexattr(b.Dir, cpuBoostXattr); err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("removing CPU boost record of %q: %w", b.Dir, err)
	}
	log.Infof("CPU limit of %q restored to %q", b.Dir, b.Max)
	return nil
}

// restoreValue sets file name in dir to want if its current value is cur.
func restoreValue(dir, name, cur, want string) error {
	val, err := getValue(dir, name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if val = strings.TrimSpace(val); val != cur {
		log.Infof("Not restoring %s in %q to %q: changed from %q to %q", name, dir, want, cur, val)
		return nil
	}
	if err := setValue(dir, name, want); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Quota returns the CPU quota and period in effect before the boost. quota
// is -1 if unlimited.
func (b *CPUBoost) Quota() (quota, period int64, err error) {
	return parseCPUQuotaAndPeriod(b.Max)
}
