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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestOtherAppRunning(t *testing.T) {
	const sandboxID = "pod"
	criSpec := func(containerType string) *specs.Spec {
		return &specs.Spec{Annotations: map[string]string{specutils.ContainerdContainerTypeAnnotation: containerType}}
	}
	type cont struct {
		id     string
		spec   *specs.Spec
		status Status
	}
	for _, tc := range []struct {
		name   string
		others []cont
		want   bool
	}{
		{
			name: "alone",
		},
		{
			name:   "running pause container",
			others: []cont{{id: sandboxID, spec: criSpec(specutils.ContainerdContainerTypeSandbox), status: Running}},
		},
		{
			name: "created app container",
			others: []cont{
				{id: sandboxID, spec: criSpec(specutils.ContainerdContainerTypeSandbox), status: Running},
				{id: "app1", spec: criSpec(specutils.ContainerdContainerTypeContainer), status: Created},
			},
		},
		{
			name: "running app container",
			others: []cont{
				{id: sandboxID, spec: criSpec(specutils.ContainerdContainerTypeSandbox), status: Running},
				{id: "app1", spec: criSpec(specutils.ContainerdContainerTypeContainer), status: Running},
			},
			want: true,
		},
		{
			name:   "running root app container",
			others: []cont{{id: sandboxID, spec: &specs.Spec{}, status: Running}},
			want:   true,
		},
		{
			name:   "unreadable state",
			others: []cont{{id: "app1"}},
			want:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := t.TempDir()
			write := func(id string, data []byte) {
				t.Helper()
				if err := os.WriteFile(buildPath(rootDir, FullID{SandboxID: sandboxID, ContainerID: id}, stateFileExtension), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, o := range tc.others {
				if o.spec == nil {
					write(o.id, []byte("{torn"))
					continue
				}
				data, err := json.Marshal(&Container{ID: o.id, Spec: o.spec, Status: o.status})
				if err != nil {
					t.Fatal(err)
				}
				write(o.id, data)
			}
			// A running app container of another sandbox whose ID has the
			// same prefix doesn't count.
			data, err := json.Marshal(&Container{ID: sandboxID + "2", Spec: &specs.Spec{}, Status: Running})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(buildPath(rootDir, FullID{SandboxID: sandboxID + "2", ContainerID: sandboxID + "2"}, stateFileExtension), data, 0o600); err != nil {
				t.Fatal(err)
			}

			c := &Container{
				ID:      "app2",
				Spec:    criSpec(specutils.ContainerdContainerTypeContainer),
				Sandbox: &sandbox.Sandbox{ID: sandboxID},
				Saver:   StateFile{RootDir: rootDir, ID: FullID{SandboxID: sandboxID, ContainerID: "app2"}},
			}
			if got := c.otherAppRunning(); got != tc.want {
				t.Errorf("otherAppRunning() = %v, want %v", got, tc.want)
			}
		})
	}
}
