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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBoostedCPUQuota(t *testing.T) {
	for _, tc := range []struct {
		quota, period int64
		minCPUs       float64
		want          int64
	}{
		{quota: 25000, period: 100000, minCPUs: 4, want: 400000},
		{quota: 10000, period: 100000, minCPUs: 4, want: 400000},
		{quota: 25000, period: 50000, minCPUs: 4, want: 200000},
		{quota: 25000, period: 100000, minCPUs: 1.125, want: 112500},
		{quota: 400000, period: 100000, minCPUs: 4, want: 400000},
		{quota: 450000, period: 100000, minCPUs: 4, want: 450000},
		{quota: -1, period: 100000, minCPUs: 4, want: -1},
		{quota: 25000, period: 100000, minCPUs: 0, want: 25000},
	} {
		got := BoostedCPUQuota(tc.quota, tc.period, tc.minCPUs)
		if got != tc.want {
			t.Errorf("BoostedCPUQuota(%d, %d, %v) = %d, want %d", tc.quota, tc.period, tc.minCPUs, got, tc.want)
		}
		if again := BoostedCPUQuota(got, tc.period, tc.minCPUs); again != got {
			t.Errorf("BoostedCPUQuota is not idempotent: BoostedCPUQuota(%d, %d, %v) = %d", got, tc.period, tc.minCPUs, again)
		}
	}
}

// newTestCgroup returns a cgroup v2 in a temporary directory with the given
// cpu.max and cpu.weight values (no file if empty).
func newTestCgroup(t *testing.T, cpuMax, cpuWeight string) *cgroupV2 {
	t.Helper()
	cg := &cgroupV2{Mountpoint: t.TempDir(), Path: "/sandbox"}
	dir := cg.MakePath("")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(dir, "user.test", []byte("x"), 0); err != nil {
		t.Skipf("user extended attributes not supported in %q: %v", dir, err)
	}
	for name, val := range map[string]string{cpuLimitCgroup: cpuMax, cpuWeightCgroup: cpuWeight} {
		if val == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return cg
}

func readTestValue(t *testing.T, cg *cgroupV2, name string) string {
	t.Helper()
	val, err := getValue(cg.MakePath(""), name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(val)
}

func TestBoostCPU(t *testing.T) {
	cg := newTestCgroup(t, "25000 100000", "100")
	if !WouldBoostCPU(cg, 4) {
		t.Errorf("WouldBoostCPU() = false, want true")
	}
	b, err := BoostCPU(cg, 4)
	if err != nil || b == nil {
		t.Fatalf("BoostCPU() = %v, %v, want a boost", b, err)
	}
	if got := readTestValue(t, cg, cpuLimitCgroup); got != "400000 100000" {
		t.Errorf("boosted cpu.max = %q, want %q", got, "400000 100000")
	}
	if got := readTestValue(t, cg, cpuWeightCgroup); got != "1600" {
		t.Errorf("boosted cpu.weight = %q, want %q", got, "1600")
	}
	if q, p, err := b.Quota(); err != nil || q != 25000 || p != 100000 {
		t.Errorf("Quota() = %d, %d, %v, want 25000, 100000, nil", q, p, err)
	}

	// Boosting again returns the recorded boost and changes nothing.
	if !WouldBoostCPU(cg, 4) {
		t.Errorf("WouldBoostCPU() on a boosted cgroup = false, want true")
	}
	if b2, err := BoostCPU(cg, 4); err != nil || b2 == nil || *b2 != *b {
		t.Errorf("BoostCPU() on a boosted cgroup = %+v, %v, want %+v", b2, err, b)
	}
	if got := readTestValue(t, cg, cpuLimitCgroup); got != "400000 100000" {
		t.Errorf("cpu.max after boosting again = %q, want %q", got, "400000 100000")
	}
	if b2, err := LoadCPUBoost(cg); err != nil || b2 == nil || *b2 != *b {
		t.Errorf("LoadCPUBoost() = %+v, %v, want %+v", b2, err, b)
	}

	if err := b.Restore(); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	if b2, err := LoadCPUBoost(cg); err != nil || b2 != nil {
		t.Errorf("LoadCPUBoost() after Restore() = %+v, %v, want nil, nil", b2, err)
	}
	if got := readTestValue(t, cg, cpuLimitCgroup); got != "25000 100000" {
		t.Errorf("restored cpu.max = %q, want %q", got, "25000 100000")
	}
	if got := readTestValue(t, cg, cpuWeightCgroup); got != "100" {
		t.Errorf("restored cpu.weight = %q, want %q", got, "100")
	}
}

func TestBoostCPUWeightCap(t *testing.T) {
	cg := newTestCgroup(t, "10000 100000", "1000")
	b, err := BoostCPU(cg, 4)
	if err != nil || b == nil {
		t.Fatalf("BoostCPU() = %v, %v, want a boost", b, err)
	}
	if got := readTestValue(t, cg, cpuWeightCgroup); got != "10000" {
		t.Errorf("boosted cpu.weight = %q, want %q", got, "10000")
	}
}

func TestBoostCPURestoreKeepsChanges(t *testing.T) {
	cg := newTestCgroup(t, "25000 100000", "100")
	b, err := BoostCPU(cg, 4)
	if err != nil || b == nil {
		t.Fatalf("BoostCPU() = %v, %v, want a boost", b, err)
	}
	// The limit is updated during the boost: Restore must keep the update.
	if err := setValue(cg.MakePath(""), cpuLimitCgroup, "50000 100000"); err != nil {
		t.Fatal(err)
	}
	if err := b.Restore(); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	if got := readTestValue(t, cg, cpuLimitCgroup); got != "50000 100000" {
		t.Errorf("cpu.max after Restore() = %q, want %q", got, "50000 100000")
	}
	if got := readTestValue(t, cg, cpuWeightCgroup); got != "100" {
		t.Errorf("cpu.weight after Restore() = %q, want %q", got, "100")
	}
}

func TestBoostCPURestoreRemovedCgroup(t *testing.T) {
	cg := newTestCgroup(t, "25000 100000", "100")
	b, err := BoostCPU(cg, 4)
	if err != nil || b == nil {
		t.Fatalf("BoostCPU() = %v, %v, want a boost", b, err)
	}
	if err := os.RemoveAll(cg.MakePath("")); err != nil {
		t.Fatal(err)
	}
	if err := b.Restore(); err != nil {
		t.Errorf("Restore() on a removed cgroup = %v, want nil", err)
	}
}

func TestBoostCPUNoop(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cg      Cgroup
		minCPUs float64
	}{
		{name: "no limit", cg: newTestCgroup(t, "max 100000", "100"), minCPUs: 4},
		{name: "high limit", cg: newTestCgroup(t, "800000 100000", "100"), minCPUs: 4},
		{name: "no cpu controller", cg: newTestCgroup(t, "", ""), minCPUs: 4},
		{name: "disabled", cg: newTestCgroup(t, "25000 100000", "100"), minCPUs: 0},
		{name: "systemd", cg: &cgroupSystemd{cgroupV2: *newTestCgroup(t, "25000 100000", "100")}, minCPUs: 4},
		{name: "v1", cg: &cgroupV1{}, minCPUs: 4},
		{name: "nil", cg: nil, minCPUs: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if WouldBoostCPU(tc.cg, tc.minCPUs) {
				t.Errorf("WouldBoostCPU() = true, want false")
			}
			if b, err := BoostCPU(tc.cg, tc.minCPUs); err != nil || b != nil {
				t.Errorf("BoostCPU() = %v, %v, want nil, nil", b, err)
			}
		})
	}
}

func TestBoostCPUWithoutWeight(t *testing.T) {
	cg := newTestCgroup(t, "25000 100000", "")
	b, err := BoostCPU(cg, 4)
	if err != nil || b == nil {
		t.Fatalf("BoostCPU() = %v, %v, want a boost", b, err)
	}
	if b.Weight != "" || b.BoostedWeight != "" {
		t.Errorf("weight boost = %q -> %q, want none", b.Weight, b.BoostedWeight)
	}
	if err := b.Restore(); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	if got := readTestValue(t, cg, cpuLimitCgroup); got != "25000 100000" {
		t.Errorf("restored cpu.max = %q, want %q", got, "25000 100000")
	}
}
