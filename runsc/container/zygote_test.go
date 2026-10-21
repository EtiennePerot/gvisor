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

package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
)

// zygoteTest holds a zygote and the configuration to adopt it.
type zygoteTest struct {
	id        string
	conf      *config.Config
	zygoteDir string
	zygote    *Container
}

// newZygote boots a zygote from spec with the given ID. Zygotes need a
// cgroup, hence root.
func newZygote(t *testing.T, conf *config.Config, id string, spec *specs.Spec) *zygoteTest {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("zygotes need a cgroup, which needs root")
	}
	zconf := *conf
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, &zconf)
	if err != nil {
		t.Fatalf("setting up zygote: %v", err)
	}
	t.Cleanup(cleanup)
	z, err := New(&zconf, Args{ID: id, Spec: spec, BundleDir: bundleDir, Zygote: true})
	if err != nil {
		t.Fatalf("creating zygote: %v", err)
	}
	t.Cleanup(func() { _ = z.Destroy() })
	if z.Sandbox.ZygoteShape == "" {
		t.Fatalf("zygote has no shape")
	}
	return &zygoteTest{id: id, conf: &zconf, zygoteDir: zconf.RootDir, zygote: z}
}

// adopt creates a root container from spec that adopts zt's zygote.
func (zt *zygoteTest) adopt(t *testing.T, spec *specs.Spec) (*Container, *config.Config) {
	t.Helper()
	conf := *zt.conf
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, &conf)
	if err != nil {
		t.Fatalf("setting up container: %v", err)
	}
	t.Cleanup(cleanup)
	c, err := New(&conf, Args{ID: zt.id, Spec: spec, BundleDir: bundleDir, AdoptZygote: zt.zygoteDir})
	if err != nil {
		t.Fatalf("creating container: %v", err)
	}
	t.Cleanup(func() { _ = c.Destroy() })
	return c, &conf
}

func (zt *zygoteTest) adopted(c *Container) bool {
	return c.Sandbox.Pid.Load() == zt.zygote.Sandbox.Pid.Load()
}

func zygoteTestSpec(t *testing.T, args ...string) *specs.Spec {
	spec := testutil.NewSpecWithArgs(args...)
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	spec.Linux.CgroupsPath = "/" + testutil.RandomContainerID()
	return spec
}

// TestZygoteAdopt checks that a container that adopts a zygote runs with its
// own process, environment, hostname and mounts.
func TestZygoteAdopt(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			dir, err := os.MkdirTemp(testutil.TmpDir(), "zygote-mount")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			if err := os.WriteFile(filepath.Join(dir, "file"), []byte("container data"), 0644); err != nil {
				t.Fatal(err)
			}
			// The template has the container's shape, but nothing else.
			zspec := zygoteTestSpec(t, "sleep", "1000")
			zspec.Hostname = "template"
			zspec.Mounts = append(zspec.Mounts, specs.Mount{Destination: dir, Type: "bind", Source: "/nonexistent"})
			id := testutil.RandomContainerID()
			zt := newZygote(t, conf, id, zspec)

			spec := zygoteTestSpec(t, "sleep", "1001")
			spec.Linux.CgroupsPath = zspec.Linux.CgroupsPath
			spec.Hostname = "actor"
			spec.Process.Env = append(spec.Process.Env, "ACTOR=yes")
			spec.Mounts = append(spec.Mounts, specs.Mount{Destination: dir, Type: "bind", Source: dir})
			c, cconf := zt.adopt(t, spec)
			if !zt.adopted(c) {
				t.Fatalf("container did not adopt the zygote")
			}
			if c.Sandbox.ZygoteShape != "" {
				t.Errorf("adopted sandbox still has a zygote shape")
			}
			if ids, err := List(zt.zygoteDir); err != nil || len(ids) != 0 {
				t.Errorf("zygote root dir still has containers %v (err: %v)", ids, err)
			}
			if err := c.Start(cconf); err != nil {
				t.Fatalf("starting container: %v", err)
			}
			for _, tc := range []struct{ cmd, want string }{
				{"cat /proc/sys/kernel/hostname", "actor"},
				// The suffix: sleep may be a multi-call binary.
				{"tr '\\0' ' ' < /proc/1/cmdline | grep -o 'sleep 1001'", "sleep 1001"},
				{"tr '\\0' '\\n' < /proc/1/environ | grep ACTOR", "ACTOR=yes"},
				{"cat " + dir + "/file", "container data"},
			} {
				out, err := executeCombinedOutput(cconf, c, nil, "/bin/sh", "-c", tc.cmd)
				if err != nil {
					t.Errorf("%q: %v", tc.cmd, err)
				} else if got := strings.TrimSpace(string(out)); got != tc.want {
					t.Errorf("%q: got %q, want %q", tc.cmd, got, tc.want)
				}
			}
		})
	}
}

// TestZygoteNoStart checks that a zygote can't be started on its own.
func TestZygoteNoStart(t *testing.T) {
	conf := testutil.TestConfig(t)
	zt := newZygote(t, conf, testutil.RandomContainerID(), zygoteTestSpec(t, "sleep", "1000"))
	if err := zt.zygote.Start(zt.conf); err == nil || !strings.Contains(err.Error(), "zygote") {
		t.Errorf("starting a zygote: got %v, want an error", err)
	}
}

// TestZygoteMismatch checks that a container that cannot adopt a zygote boots
// a new sandbox and leaves the zygote alone.
func TestZygoteMismatch(t *testing.T) {
	conf := testutil.TestConfig(t)
	id := testutil.RandomContainerID()
	zspec := zygoteTestSpec(t, "sleep", "1000")
	for _, tc := range []struct {
		name   string
		mutate func(*specs.Spec)
	}{
		{"cgroup", func(s *specs.Spec) { s.Linux.CgroupsPath = "/" + testutil.RandomContainerID() }},
		{"annotations", func(s *specs.Spec) { s.Annotations = map[string]string{"other": "shape"} }},
		{"mounts", func(s *specs.Spec) {
			s.Mounts = append(s.Mounts, specs.Mount{Destination: "/extra", Type: "tmpfs", Source: "tmpfs"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zt := newZygote(t, conf, id, zspec)
			spec := zygoteTestSpec(t, "sleep", "1000")
			spec.Linux.CgroupsPath = zspec.Linux.CgroupsPath
			tc.mutate(spec)
			c, cconf := zt.adopt(t, spec)
			if zt.adopted(c) {
				t.Fatalf("container adopted a zygote of another shape")
			}
			if err := c.Start(cconf); err != nil {
				t.Fatalf("starting container: %v", err)
			}
			// The zygote is still there, and still a zygote.
			z, err := Load(zt.zygoteDir, FullID{SandboxID: id, ContainerID: id}, LoadOpts{Exact: true})
			if err != nil {
				t.Fatalf("loading zygote: %v", err)
			}
			if z.Sandbox.ZygoteShape == "" || z.Status != Created {
				t.Errorf("zygote changed: shape %q, status %v", z.Sandbox.ZygoteShape, z.Status)
			}
		})
	}
}

// TestZygoteDead checks that a container that finds its zygote dead boots a
// new sandbox.
func TestZygoteDead(t *testing.T) {
	conf := testutil.TestConfig(t)
	id := testutil.RandomContainerID()
	zspec := zygoteTestSpec(t, "sleep", "1000")
	zt := newZygote(t, conf, id, zspec)
	pid := zt.zygote.Sandbox.Pid.Load()
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		t.Fatalf("killing zygote: %v", err)
	}
	// The zygote is a child of the test.
	if _, err := unix.Wait4(pid, nil, 0, nil); err != nil {
		t.Fatalf("waiting for zygote: %v", err)
	}
	spec := zygoteTestSpec(t, "sleep", "1000")
	spec.Linux.CgroupsPath = zspec.Linux.CgroupsPath
	c, cconf := zt.adopt(t, spec)
	if zt.adopted(c) {
		t.Fatalf("container adopted a dead zygote")
	}
	if err := c.Start(cconf); err != nil {
		t.Fatalf("starting container: %v", err)
	}
}

// TestZygoteRestore checks that "runsc restore" can adopt a zygote.
func TestZygoteRestore(t *testing.T) {
	conf := testutil.TestConfig(t)
	spec := zygoteTestSpec(t, "sleep", "1000")
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("setting up container: %v", err)
	}
	defer cleanup()
	id := testutil.RandomContainerID()
	c, err := New(conf, Args{ID: id, Spec: spec, BundleDir: bundleDir})
	if err != nil {
		t.Fatalf("creating container: %v", err)
	}
	if err := c.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}
	imageDir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(imageDir)
	if err := c.Checkpoint(conf, imageDir, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("checkpointing: %v", err)
	}
	if _, err := c.Wait(); err != nil {
		t.Fatalf("waiting: %v", err)
	}
	if err := c.Destroy(); err != nil {
		t.Fatalf("destroying: %v", err)
	}

	zt := newZygote(t, conf, id, spec)
	c2, cconf := zt.adopt(t, spec)
	if !zt.adopted(c2) {
		t.Fatalf("container did not adopt the zygote")
	}
	if err := c2.Restore(cconf, imageDir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	if out, err := executeCombinedOutput(cconf, c2, nil, "/bin/sh", "-c", "tr '\\0' ' ' < /proc/1/cmdline | grep -o 'sleep 1000'"); err != nil {
		t.Errorf("exec: %v", err)
	} else if got := strings.TrimSpace(string(out)); got != "sleep 1000" {
		t.Errorf("restored init: got %q, want %q", got, "sleep 1000")
	}
}
