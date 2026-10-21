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
	"testing"
)

func TestPrioritizeOwnCgroup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		own     string
		sandbox string
		weight  string // Initial cpu.weight of own cgroup; empty means no file.
		raised  bool
		want    string
		wantErr bool
	}{
		{
			name:    "sibling",
			own:     "/ctl",
			sandbox: "/sbx",
			weight:  "100\n",
			raised:  true,
			want:    "10000",
		},
		{
			name:    "nested sibling",
			own:     "/a/b/ctl",
			sandbox: "/a/b/sbx",
			weight:  "1\n",
			raised:  true,
			want:    "10000",
		},
		{
			name:    "unclean paths",
			own:     "a/b/ctl/",
			sandbox: "/a//b/sbx",
			weight:  "100\n",
			raised:  true,
			want:    "10000",
		},
		{
			name:    "already max",
			own:     "/ctl",
			sandbox: "/sbx",
			weight:  "10000\n",
			want:    "10000\n",
		},
		{
			name:    "not sibling",
			own:     "/system/runtime",
			sandbox: "/pods/sbx",
			weight:  "100\n",
			want:    "100\n",
		},
		{
			name:    "sandbox is nephew",
			own:     "/a/ctl",
			sandbox: "/a/pods/sbx",
			weight:  "100\n",
			want:    "100\n",
		},
		{
			name:    "sandbox is child",
			own:     "/a",
			sandbox: "/a/sbx",
			weight:  "100\n",
			want:    "100\n",
		},
		{
			name:    "same cgroup",
			own:     "/a/sbx",
			sandbox: "/a/sbx",
			weight:  "100\n",
			want:    "100\n",
		},
		{
			name:    "root cgroup",
			own:     "/",
			sandbox: "/sbx",
		},
		{
			name:    "systemd service",
			own:     "/system.slice/containerd.service",
			sandbox: "/system.slice/sbx",
			weight:  "100\n",
			want:    "100\n",
		},
		{
			name:    "systemd scope",
			own:     "/user.slice/session-1.scope",
			sandbox: "/user.slice/sbx",
			weight:  "100\n",
			want:    "100\n",
		},
		{
			name:    "no cpu controller",
			own:     "/ctl",
			sandbox: "/sbx",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mnt := t.TempDir()
			ownDir := filepath.Join(mnt, tc.own)
			if err := os.MkdirAll(ownDir, 0755); err != nil {
				t.Fatal(err)
			}
			weightFile := filepath.Join(ownDir, "cpu.weight")
			if tc.weight != "" {
				if err := os.WriteFile(weightFile, []byte(tc.weight), 0644); err != nil {
					t.Fatal(err)
				}
			}
			raised, err := prioritizeOwnCgroup(mnt, tc.own, tc.sandbox)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("prioritizeOwnCgroup() error = %v, wantErr %t", err, tc.wantErr)
			}
			if raised != tc.raised {
				t.Errorf("prioritizeOwnCgroup() = %t, want %t", raised, tc.raised)
			}
			if tc.weight == "" {
				return
			}
			got, err := os.ReadFile(weightFile)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("cpu.weight = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPrioritizeOwnCgroupIgnoresOtherDrivers(t *testing.T) {
	for _, cg := range []Cgroup{
		&cgroupV1{Name: "/sbx"},
		&cgroupSystemd{cgroupV2: cgroupV2{Mountpoint: t.TempDir(), Path: "/system.slice/sbx.scope"}},
	} {
		if raised, err := PrioritizeOwnCgroup(cg); raised || err != nil {
			t.Errorf("PrioritizeOwnCgroup(%T) = %t, %v, want false, nil", cg, raised, err)
		}
	}
}
