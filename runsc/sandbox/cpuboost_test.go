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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
)

const testSandboxID = "sandbox"

type cpuBoostTest struct {
	t       *testing.T
	conf    *config.Config
	cg      cgroup.Cgroup
	cgroupD string
}

// newCPUBoostTest returns a test environment with a cgroup v2 in a temporary
// directory that has the given cpu.max.
func newCPUBoostTest(t *testing.T, cpuMax string) *cpuBoostTest {
	mnt := t.TempDir()
	dir := filepath.Join(mnt, "sandbox")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{"cpu.max": cpuMax, "cpu.weight": "100"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Setxattr(dir, "user.test", []byte("x"), 0); err != nil {
		t.Skipf("user extended attributes not supported in %q: %v", dir, err)
	}
	var cg cgroup.CgroupJSON
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"cgroupv2": {"mountpoint": %q, "path": "/sandbox"}}`, mnt)), &cg); err != nil {
		t.Fatal(err)
	}
	conf := &config.Config{
		RootDir:                            t.TempDir(),
		TestOnlyLifecycleCPUBoostMilliCPUs: -1,
	}
	return &cpuBoostTest{t: t, conf: conf, cg: cg.Cgroup, cgroupD: dir}
}

func (c *cpuBoostTest) cpuMax() string {
	c.t.Helper()
	b, err := os.ReadFile(filepath.Join(c.cgroupD, "cpu.max"))
	if err != nil {
		c.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func (c *cpuBoostTest) wantCPUMax(want string) {
	c.t.Helper()
	if got := c.cpuMax(); got != want {
		c.t.Errorf("cpu.max = %q, want %q", got, want)
	}
}

func (c *cpuBoostTest) boost() *CPUBoost {
	return BoostCPU(c.conf, c.cg, testSandboxID)
}

func (c *cpuBoostTest) rootDirFiles() []string {
	c.t.Helper()
	ents, err := os.ReadDir(c.conf.RootDir)
	if err != nil {
		c.t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestCPUBoostEnd(t *testing.T) {
	c := newCPUBoostTest(t, "25000 100000")
	b := c.boost()
	if b == nil {
		t.Fatalf("BoostCPU() = nil, want a boost")
	}
	if q, p, err := b.Quota(); err != nil || q != 25000 || p != 100000 {
		t.Errorf("Quota() = %d, %d, %v, want 25000, 100000, nil", q, p, err)
	}
	c.wantCPUMax("400000 100000")
	b.End()
	c.wantCPUMax("25000 100000")
}

func TestCPUBoostNested(t *testing.T) {
	c := newCPUBoostTest(t, "25000 100000")
	b1 := c.boost()
	b2 := c.boost()
	if b1 == nil || b2 == nil {
		t.Fatalf("BoostCPU() = %v, %v, want two holds", b1, b2)
	}
	if q, _, _ := b2.Quota(); q != 25000 {
		t.Errorf("second hold's Quota() = %d, want 25000", q)
	}
	b1.End()
	c.wantCPUMax("400000 100000")
	b2.End()
	c.wantCPUMax("25000 100000")
}

// A killed runsc command releases its hold without restoring the limit, like
// Release does.
func TestCPUBoostKilledHolder(t *testing.T) {
	c := newCPUBoostTest(t, "25000 100000")
	c.boost().Release()
	c.wantCPUMax("400000 100000")
	b := c.boost()
	if b == nil {
		t.Fatalf("BoostCPU() on a boosted sandbox = nil, want a hold")
	}
	b.End()
	c.wantCPUMax("25000 100000")
}

// A runsc command killed while it holds the boost of a sandbox leaves the
// limit raised. Another sandbox later created in the same cgroup, with
// another root directory, restores it.
func TestCPUBoostAbandoned(t *testing.T) {
	c := newCPUBoostTest(t, "25000 100000")
	c.boost().Release()
	c.wantCPUMax("400000 100000")
	c.conf.RootDir = t.TempDir()
	b := BoostCPU(c.conf, c.cg, "other")
	if b == nil {
		t.Fatalf("BoostCPU() on an abandoned boost = nil, want a hold")
	}
	if q, p, err := b.Quota(); err != nil || q != 25000 || p != 100000 {
		t.Errorf("Quota() = %d, %d, %v, want 25000, 100000, nil", q, p, err)
	}
	b.End()
	c.wantCPUMax("25000 100000")
}

func TestEndCPUBoost(t *testing.T) {
	c := newCPUBoostTest(t, "25000 100000")
	held := c.boost()
	c.wantCPUMax("400000 100000")
	EndCPUBoost(c.conf.RootDir, testSandboxID, c.cg)
	c.wantCPUMax("25000 100000")
	if files := c.rootDirFiles(); len(files) != 0 {
		t.Errorf("files left in the root directory: %v", files)
	}
	// The remaining hold ends without effect, and without leaving files.
	held.End()
	c.wantCPUMax("25000 100000")
	if files := c.rootDirFiles(); len(files) != 0 {
		t.Errorf("files left in the root directory: %v", files)
	}
	// Nothing to do on a sandbox that isn't boosted.
	EndCPUBoost(c.conf.RootDir, testSandboxID, c.cg)
}

func TestCPUBoostHandOver(t *testing.T) {
	c := newCPUBoostTest(t, "25000 100000")
	b := c.boost()
	fd, err := unix.Dup(int(b.holder.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	b.Release()
	// The duplicate still holds the boost.
	c.boost().End()
	c.wantCPUMax("400000 100000")
	HeldCPUBoost(c.conf.RootDir, testSandboxID, c.cg, fd).End()
	c.wantCPUMax("25000 100000")
}

func TestCPUBoostNoop(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cpuMax    string
		milliCPUs int
	}{
		{name: "no limit", cpuMax: "max 100000", milliCPUs: -1},
		{name: "high limit", cpuMax: "400000 100000", milliCPUs: -1},
		{name: "disabled", cpuMax: "25000 100000", milliCPUs: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCPUBoostTest(t, tc.cpuMax)
			c.conf.TestOnlyLifecycleCPUBoostMilliCPUs = tc.milliCPUs
			b := c.boost()
			if b != nil {
				t.Errorf("BoostCPU() = %+v, want nil", b)
			}
			// End on nil is fine.
			b.End()
			b.Release()
			c.wantCPUMax(tc.cpuMax)
			if files := c.rootDirFiles(); len(files) != 0 {
				t.Errorf("files created in the root directory: %v", files)
			}
		})
	}
}

func TestCPUBoostOverride(t *testing.T) {
	c := newCPUBoostTest(t, "25000 100000")
	c.conf.TestOnlyLifecycleCPUBoostMilliCPUs = 1125
	b := c.boost()
	c.wantCPUMax("112500 100000")
	b.End()
	c.wantCPUMax("25000 100000")
}
