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
	"encoding/json"
	"os"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// actorSpec returns the spec of a container named by actor, with everything
// that differs between containers of the same shape derived from it.
func actorSpec(actor string) *specs.Spec {
	return &specs.Spec{
		Process: &specs.Process{
			Args: []string{"/bin/" + actor, "--secret=" + actor},
			Env:  []string{"TOKEN=" + actor},
			Cwd:  "/home/" + actor,
			User: specs.User{UID: 1000, GID: 1000},
			Capabilities: &specs.LinuxCapabilities{
				Bounding: []string{"CAP_CHOWN", "CAP_KILL"},
			},
		},
		Root:       &specs.Root{Path: "/bundles/" + actor + "/rootfs"},
		Hostname:   actor + ".example.com",
		Domainname: actor + ".example",
		Hooks:      &specs.Hooks{Prestart: []specs.Hook{{Path: "/bin/hook-" + actor}}},
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "/bundles/" + actor + "/proc"},
			{Destination: "/data", Type: "bind", Source: "/volumes/" + actor, Options: []string{"rbind"}},
			{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs"},
		},
		Annotations: map[string]string{"shape": "small"},
		Linux: &specs.Linux{
			CgroupsPath: "/pool/leaf-1",
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.NetworkNamespace, Path: "/var/run/netns/" + actor},
			},
			Resources: &specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: new(int64)}},
		},
	}
}

func testConf(t *testing.T, args ...string) *config.Config {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	config.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parsing flags: %v", err)
	}
	conf, err := config.NewFromFlags(fs)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return conf
}

func mustZygoteSpec(t *testing.T, spec *specs.Spec, bundleDir string) *specs.Spec {
	t.Helper()
	z, err := zygoteSpec(spec, bundleDir)
	if err != nil {
		t.Fatalf("zygoteSpec: %v", err)
	}
	return z
}

func TestZygoteSpecHasNothingContainerSpecific(t *testing.T) {
	spec := actorSpec("alice")
	z := mustZygoteSpec(t, spec, "/bundles/alice")
	b, err := json.Marshal(z)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "alice") {
		t.Errorf("zygote spec mentions the container: %s", b)
	}
	// The original spec is unchanged.
	if spec.Process.Args[0] != "/bin/alice" || spec.Mounts[1].Source != "/volumes/alice" {
		t.Errorf("zygoteSpec modified its argument: %+v", spec)
	}
	// What remains is still a valid spec for a root container.
	if len(z.Process.Args) == 0 || z.Root.Path == "" || z.Mounts[1].Source == "" {
		t.Errorf("zygote spec lacks mandatory fields: %s", b)
	}
	if _, err := os.Stat(zygotePlaceholder); err == nil {
		t.Errorf("%q exists", zygotePlaceholder)
	}
}

func TestZygoteShape(t *testing.T) {
	conf := testConf(t, "--root=/run/a", "--platform=systrap")
	hash := func(spec *specs.Spec, bundleDir string, conf *config.Config, ids ...string) string {
		t.Helper()
		h, err := hashZygoteShape(mustZygoteSpec(t, spec, bundleDir), conf, ids...)
		if err != nil {
			t.Fatalf("hashZygoteShape: %v", err)
		}
		return h
	}
	want := hash(actorSpec("alice"), "/bundles/alice", conf, "runsc", "sentry")

	for _, tc := range []struct {
		name   string
		mutate func(*specs.Spec)
		conf   *config.Config
		ids    []string
		same   bool
	}{
		{name: "other container", same: true},
		{name: "other capability order", mutate: func(s *specs.Spec) {
			s.Process.Capabilities.Bounding = []string{"CAP_KILL", "CAP_CHOWN"}
		}, same: true},
		{name: "other capabilities", mutate: func(s *specs.Spec) {
			s.Process.Capabilities.Bounding = []string{"CAP_KILL"}
		}},
		{name: "other root dir", conf: testConf(t, "--root=/run/b", "--platform=systrap"), same: true},
		{name: "other flags", conf: testConf(t, "--root=/run/a", "--platform=systrap", "--debug")},
		{name: "other runsc", ids: []string{"runsc2", "sentry"}},
		{name: "other sentry", ids: []string{"runsc", "sentry2"}},
		{name: "other cgroup", mutate: func(s *specs.Spec) { s.Linux.CgroupsPath = "/pool/leaf-2" }},
		{name: "other resources", mutate: func(s *specs.Spec) { s.Linux.Resources = nil }},
		{name: "other annotations", mutate: func(s *specs.Spec) { s.Annotations["shape"] = "large" }},
		{name: "other user", mutate: func(s *specs.Spec) { s.Process.User.UID = 0 }},
		{name: "other mount destination", mutate: func(s *specs.Spec) { s.Mounts[1].Destination = "/other" }},
		{name: "other mount type", mutate: func(s *specs.Spec) { s.Mounts[2].Type = "bind"; s.Mounts[2].Source = "/x" }},
		{name: "extra mount", mutate: func(s *specs.Spec) { s.Mounts = append(s.Mounts, specs.Mount{Destination: "/y", Type: "tmpfs"}) }},
		{name: "no network namespace", mutate: func(s *specs.Spec) { s.Linux.Namespaces = s.Linux.Namespaces[:1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := actorSpec("bob")
			if tc.mutate != nil {
				tc.mutate(spec)
			}
			c := conf
			if tc.conf != nil {
				c = tc.conf
			}
			ids := []string{"runsc", "sentry"}
			if tc.ids != nil {
				ids = tc.ids
			}
			if got := hash(spec, "/bundles/bob", c, ids...); (got == want) != tc.same {
				t.Errorf("same shape = %t, want %t", got == want, tc.same)
			}
		})
	}
}

func TestZygoteIneligible(t *testing.T) {
	eligible := func() (*config.Config, *Args) {
		spec := actorSpec("alice")
		return testConf(t, "--network=sandbox"), &Args{ID: "alice", Spec: spec, BundleDir: "/bundles/alice"}
	}
	if conf, args := eligible(); zygoteIneligible(conf, args) != "" {
		t.Fatalf("eligible container is ineligible: %s", zygoteIneligible(conf, args))
	}
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config, *Args)
	}{
		{"subcontainer", func(_ *config.Config, a *Args) {
			a.Spec.Annotations["io.kubernetes.cri.container-type"] = "container"
			a.Spec.Annotations["io.kubernetes.cri.sandbox-id"] = "pod"
		}},
		{"no root container", func(_ *config.Config, a *Args) { a.NoRootContainer = true }},
		{"fs restore", func(_ *config.Config, a *Args) { a.FSRestoreImagePaths = []string{"/img"} }},
		{"pass files", func(_ *config.Config, a *Args) { a.PassFiles = map[int]*os.File{3: os.Stdin} }},
		{"terminal", func(_ *config.Config, a *Args) { a.Spec.Process.Terminal = true }},
		{"console", func(_ *config.Config, a *Args) { a.ConsoleSocket = "/sock" }},
		{"user log", func(_ *config.Config, a *Args) { a.UserLog = "/log" }},
		{"attached", func(_ *config.Config, a *Args) { a.Attached = true }},
		{"host network", func(c *config.Config, _ *Args) { c.Network = config.NetworkHost }},
		{"rootless", func(c *config.Config, _ *Args) { c.Rootless = true }},
		{"ignore cgroups", func(c *config.Config, _ *Args) { c.IgnoreCgroups = true }},
		{"no cgroup", func(_ *config.Config, a *Args) { a.Spec.Linux.CgroupsPath = "" }},
		{"systemd cgroup", func(c *config.Config, _ *Args) { c.SystemdCgroup = true }},
		{"systemd cgroup path", func(_ *config.Config, a *Args) { a.Spec.Linux.CgroupsPath = "system.slice:runsc:alice" }},
		{"cgroup parent", func(_ *config.Config, a *Args) { a.Spec.Annotations[cgroupParentAnnotation] = "/pod" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, args := eligible()
			tc.mutate(conf, args)
			if why := zygoteIneligible(conf, args); why == "" {
				t.Errorf("zygoteIneligible = \"\", want a reason")
			}
		})
	}
}
