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
	"testing"

	"gvisor.dev/gvisor/runsc/config"
)

// fakeCPUFreq creates a fake cpufreq sysfs directory with one policy per
// governor and returns the corresponding setting.
func fakeCPUFreq(t *testing.T, governors ...string) cpuGovernorSetting {
	t.Helper()
	s := cpuGovernorSetting{dir: t.TempDir()}
	for i, g := range governors {
		p := s.governorPath(fmt.Sprintf("policy%d", i))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(g+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (s cpuGovernorSetting) governors(t *testing.T) []string {
	t.Helper()
	var govs []string
	for i := 0; ; i++ {
		b, err := os.ReadFile(s.governorPath(fmt.Sprintf("policy%d", i)))
		if os.IsNotExist(err) {
			return govs
		}
		if err != nil {
			t.Fatal(err)
		}
		govs = append(govs, strings.TrimSpace(string(b)))
	}
}

func TestCPUGovernor(t *testing.T) {
	conf := &config.Config{}
	for _, tc := range []struct {
		name      string
		governors []string
		wantDelta bool
		wantAfter []string
	}{
		{
			name: "no cpufreq",
		},
		{
			name:      "performance",
			governors: []string{"performance", "performance"},
		},
		{
			// Only policy0 is checked.
			name:      "policy0 performance",
			governors: []string{"performance", "powersave"},
		},
		{
			name:      "policy0 userspace",
			governors: []string{"userspace", "powersave"},
		},
		{
			name:      "powersave",
			governors: []string{"powersave", "powersave"},
			wantDelta: true,
			wantAfter: []string{"performance", "performance"},
		},
		{
			name:      "mixed",
			governors: []string{"schedutil", "userspace", "performance", "ondemand"},
			wantDelta: true,
			wantAfter: []string{"performance", "userspace", "performance", "performance"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fakeCPUFreq(t, tc.governors...)
			d, err := s.Delta(conf)
			if err != nil {
				t.Fatalf("Delta: %v", err)
			}
			if got := d != nil; got != tc.wantDelta {
				t.Fatalf("Delta = %+v, want delta: %v", d, tc.wantDelta)
			}
			if d == nil {
				return
			}
			if d.FromValue != tc.governors[0] || d.ToValue != "performance" || d.Mandatory {
				t.Errorf("Delta = %+v, want non-mandatory %q -> %q", d, tc.governors[0], "performance")
			}
			if err := d.Apply(); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if got := s.governors(t); strings.Join(got, ",") != strings.Join(tc.wantAfter, ",") {
				t.Errorf("governors after Apply = %v, want %v", got, tc.wantAfter)
			}
			if d, err := s.Delta(conf); err != nil || d != nil {
				t.Errorf("Delta after Apply = %+v, %v; want nil, nil", d, err)
			}
		})
	}
}

func TestCPUGovernorApplyFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write read-only files")
	}
	s := fakeCPUFreq(t, "powersave")
	if err := os.Chmod(s.governorPath("policy0"), 0444); err != nil {
		t.Fatal(err)
	}
	d, err := s.Delta(&config.Config{})
	if err != nil || d == nil {
		t.Fatalf("Delta = %+v, %v; want non-nil delta", d, err)
	}
	if err := d.Apply(); err == nil {
		t.Errorf("Apply succeeded on a read-only governor file")
	}
}
