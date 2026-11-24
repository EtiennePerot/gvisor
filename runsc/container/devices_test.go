// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestParseDeviceMajors(t *testing.T) {
	const procDevices = `Character devices:
  1 mem
195 nvidia
235 nvidia-caps
510 nvidia-uvm

Block devices:
  8 sd
`
	got, err := parseDeviceMajors(strings.NewReader(procDevices), []string{"nvidia-uvm", "nvidia-caps"})
	if err != nil {
		t.Fatalf("parseDeviceMajors(): %v", err)
	}
	if want := []int64{235, 510}; !slices.Equal(got, want) {
		t.Errorf("parseDeviceMajors() = %v, want %v", got, want)
	}
}

// fakeHostDevices replaces the devices that the package thinks are needed.
func fakeHostDevices(t *testing.T, capEnabled bool, paths ...string) {
	t.Helper()
	oldCap, oldRule := cpuIdleStateCapEnabled, hostDeviceRule
	t.Cleanup(func() { cpuIdleStateCapEnabled, hostDeviceRule = oldCap, oldRule })
	cpuIdleStateCapEnabled = func(*specs.Spec, *config.Config) bool { return capEnabled }
	hostDeviceRule = func(path, access string) (cgroup.DeviceRule, error) {
		if i := slices.Index(paths, path); i >= 0 {
			return cgroup.DeviceRule{Type: "c", Major: 1000, Minor: int64(i), Access: access}, nil
		}
		return cgroup.DeviceRule{}, os.ErrNotExist
	}
}

func TestSandboxDeviceRulesHostDevices(t *testing.T) {
	paths := []string{"/dev/cpu_dma_latency", "/dev/kvm", "/dev/nvidia0", "/dev/nvidia-modeset", "/dev/sda", "/dev/nvidiactl", "/dev/vfio/0", "/dev/vfio/../sda", "/dev/nvidia-caps-imex-channels/channel0", "/dev/nvidia-caps/nvidia-cap1"}
	// A privileged container's spec lists every host device.
	// Listing /dev/nvidiactl requests GPU functionality.
	privileged := &specs.Linux{}
	for _, path := range paths[:5] /* Excludes "/dev/nvidiactl" onwards */ {
		privileged.Devices = append(privileged.Devices, specs.LinuxDevice{Path: path, Type: "c"})
	}
	privilegedGPU := &specs.Linux{Devices: append(slices.Clone(privileged.Devices), specs.LinuxDevice{Path: "/dev/nvidiactl", Type: "c"})}
	root := &specs.Root{Path: "/"}
	sub := map[string]string{
		specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeContainer,
	}
	passthrough := config.CharDevPassthrough
	for _, tc := range []struct {
		name       string
		capEnabled bool
		conf       *config.Config
		spec       *specs.Spec
		// want maps device paths to their access in the rules.
		want map[string]string
	}{
		{
			name: "default",
			conf: &config.Config{Platform: "systrap"},
			spec: &specs.Spec{},
			want: map[string]string{},
		},
		{
			name:       "cap",
			capEnabled: true,
			conf:       &config.Config{Platform: "systrap"},
			spec:       &specs.Spec{},
			want:       map[string]string{"/dev/cpu_dma_latency": "w"},
		},
		{
			name:       "cap subcontainer",
			capEnabled: true,
			conf:       &config.Config{Platform: "systrap"},
			spec:       &specs.Spec{Annotations: sub},
			want:       map[string]string{},
		},
		{
			name: "privileged",
			conf: &config.Config{Platform: "systrap"},
			spec: &specs.Spec{Linux: privileged},
			want: map[string]string{},
		},
		{
			name:       "privileged cap",
			capEnabled: true,
			conf:       &config.Config{Platform: "systrap"},
			spec:       &specs.Spec{Linux: privileged},
			want:       map[string]string{"/dev/cpu_dma_latency": "w"},
		},
		{
			name: "privileged nvproxy",
			conf: &config.Config{Platform: "systrap", NVProxy: true},
			spec: &specs.Spec{Root: root, Linux: privileged},
			want: map[string]string{},
		},
		{
			name: "privileged gpu",
			conf: &config.Config{Platform: "systrap"},
			spec: &specs.Spec{Root: root, Linux: privilegedGPU},
			want: map[string]string{"/dev/nvidia0": "rw", "/dev/nvidiactl": "rw"},
		},
		{
			name: "gpu imex",
			conf: &config.Config{Platform: "systrap"},
			spec: &specs.Spec{Root: root, Linux: &specs.Linux{Devices: []specs.LinuxDevice{
				{Path: "/dev/nvidiactl", Type: "c"},
				{Path: "/dev/nvidia0", Type: "c"},
				{Path: "/dev/nvidia-caps-imex-channels/channel0", Type: "c"},
				{Path: "/dev/nvidia-caps/nvidia-cap1", Type: "c"},
			}}},
			want: map[string]string{"/dev/nvidiactl": "rw", "/dev/nvidia0": "rw", "/dev/nvidia-caps-imex-channels/channel0": "rw", "/dev/nvidia-caps/nvidia-cap1": "rw"},
		},
		{
			name: "nvproxy imex without device gofer",
			conf: &config.Config{Platform: "systrap", NVProxy: true},
			spec: &specs.Spec{Root: root, Linux: &specs.Linux{Devices: []specs.LinuxDevice{
				{Path: "/dev/nvidia-caps-imex-channels/channel0", Type: "c"},
			}}},
			want: map[string]string{},
		},
		{
			name: "tpu imex without nvproxy",
			conf: &config.Config{Platform: "systrap"},
			spec: &specs.Spec{Root: root, Linux: &specs.Linux{Devices: []specs.LinuxDevice{
				{Path: "/dev/vfio/0", Type: "c"},
				{Path: "/dev/nvidia-caps-imex-channels/channel0", Type: "c"},
			}}},
			want: map[string]string{"/dev/vfio/0": "rw"},
		},
		{
			name: "no root container gpu",
			conf: &config.Config{Platform: "systrap"},
			spec: &specs.Spec{Linux: privilegedGPU},
			want: map[string]string{},
		},
		{
			name: "tpu",
			conf: &config.Config{Platform: "systrap"},
			spec: &specs.Spec{Root: root, Linux: &specs.Linux{Devices: []specs.LinuxDevice{
				{Path: "/dev/vfio/0", Type: "c"},
				{Path: "/dev/vfio/../sda", Type: "c"}, // Unclean
			}}},
			want: map[string]string{"/dev/vfio/0": "rw"},
		},
		{
			name: "privileged passthrough",
			conf: &config.Config{Platform: "systrap", CharacterDevicePolicy: passthrough},
			spec: &specs.Spec{Linux: privileged},
			want: map[string]string{"/dev/cpu_dma_latency": "rw", "/dev/kvm": "rw", "/dev/nvidia0": "rw", "/dev/nvidia-modeset": "rw", "/dev/sda": "rw"},
		},
		{
			name: "passthrough without devices",
			conf: &config.Config{Platform: "systrap", CharacterDevicePolicy: passthrough},
			spec: &specs.Spec{},
			want: map[string]string{},
		},
		{
			name: "privileged prefer emulated",
			conf: &config.Config{Platform: "systrap", CharacterDevicePolicy: config.CharDevPreferEmulated},
			spec: &specs.Spec{Linux: privileged},
			want: map[string]string{"/dev/cpu_dma_latency": "rw", "/dev/kvm": "rw", "/dev/nvidia0": "rw", "/dev/nvidia-modeset": "rw", "/dev/sda": "rw"},
		},
		{
			name: "kvm platform",
			conf: &config.Config{Platform: "kvm"},
			spec: &specs.Spec{},
			want: map[string]string{"/dev/kvm": "rw"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeHostDevices(t, tc.capEnabled, paths...)
			rules, err := sandboxDeviceRules(tc.conf, tc.spec)
			if err != nil {
				t.Fatalf("sandboxDeviceRules(): %v", err)
			}
			got := map[string]string{}
			for _, r := range rules {
				if r.Major == 1000 { // Added by `fakeHostDevices`.
					got[paths[r.Minor]] += r.Access
				}
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("sandboxDeviceRules() allows %v, want %v", got, tc.want)
			}
		})
	}
}
