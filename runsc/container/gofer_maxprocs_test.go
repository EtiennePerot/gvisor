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
	"errors"
	"runtime"
	"testing"

	"gvisor.dev/gvisor/runsc/cgroup"
)

type fakeCPUCgroup struct {
	cgroup.Cgroup
	numCPU    int
	numCPUErr error
	quota     int64
	period    int64
	quotaErr  error
}

func (f *fakeCPUCgroup) NumCPU() (int, error)      { return f.numCPU, f.numCPUErr }
func (f *fakeCPUCgroup) CPUQuota() (int64, error)  { return f.quota, f.quotaErr }
func (f *fakeCPUCgroup) CPUPeriod() (int64, error) { return f.period, nil }
func (f *fakeCPUCgroup) MakePath(string) string    { return "/fake" }

func TestGoferGOMAXPROCS(t *testing.T) {
	hostCPUs := runtime.NumCPU()
	for _, tc := range []struct {
		name string
		cg   cgroup.Cgroup
		want int
	}{
		{
			name: "no cgroup",
			want: min(hostCPUs, goferMaxProcs),
		},
		{
			name: "no limit",
			cg:   &fakeCPUCgroup{numCPU: 192, quota: -1, period: 100000},
			want: min(hostCPUs, goferMaxProcs),
		},
		{
			name: "cpuset smaller than cap",
			cg:   &fakeCPUCgroup{numCPU: 1, quota: -1, period: 100000},
			want: 1,
		},
		{
			name: "fractional quota rounds up to 2",
			cg:   &fakeCPUCgroup{numCPU: 192, quota: 25000, period: 100000},
			want: min(hostCPUs, 2),
		},
		{
			name: "quota rounds up",
			cg:   &fakeCPUCgroup{numCPU: 192, quota: 250000, period: 100000},
			want: min(hostCPUs, 3),
		},
		{
			name: "quota above cap",
			cg:   &fakeCPUCgroup{numCPU: 192, quota: 6400000, period: 100000},
			want: min(hostCPUs, goferMaxProcs),
		},
		{
			name: "cpuset error falls back to host CPUs",
			cg:   &fakeCPUCgroup{numCPUErr: errors.New("no cpuset"), quota: 300000, period: 100000},
			want: min(hostCPUs, 3),
		},
		{
			name: "quota error ignores cgroup",
			cg:   &fakeCPUCgroup{numCPU: 1, quotaErr: errors.New("no cpu.max")},
			want: min(hostCPUs, goferMaxProcs),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := goferGOMAXPROCS(tc.cg); got != tc.want {
				t.Errorf("goferGOMAXPROCS() = %d, want %d", got, tc.want)
			}
		})
	}
}
