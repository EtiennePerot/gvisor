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
	"os/exec"
	"testing"

	"gvisor.dev/gvisor/runsc/specutils"
)

// TestLiveGoferPid checks that a container whose gofer has exited does not
// signal or wait for an unrelated process that reused the gofer's PID.
func TestLiveGoferPid(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "100")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting sleep: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	pid := cmd.Process.Pid
	startTime, err := specutils.ProcessStartTime(pid)
	if err != nil {
		t.Fatalf("ProcessStartTime(%d): %v", pid, err)
	}

	for _, tc := range []struct {
		name      string
		startTime uint64
		isChild   bool
		want      int
	}{
		{
			name:      "gofer",
			startTime: startTime,
			want:      pid,
		},
		{
			name:      "reused PID",
			startTime: startTime + 1,
			want:      0,
		},
		{
			name:      "child",
			startTime: startTime + 1,
			isChild:   true,
			want:      pid,
		},
		{
			name: "unknown start time",
			want: pid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Container{ID: "test", GoferStartTime: tc.startTime, goferIsChild: tc.isChild}
			c.GoferPid.Store(pid)
			if got := c.liveGoferPid(); got != tc.want {
				t.Errorf("liveGoferPid() = %d, want %d", got, tc.want)
			}
			if got := c.GoferPid.Load(); got != tc.want {
				t.Errorf("GoferPid after liveGoferPid() = %d, want %d", got, tc.want)
			}
		})
	}

	// A gofer that has exited and been reaped.
	cmd.Process.Kill()
	cmd.Wait()
	c := &Container{ID: "test", GoferStartTime: startTime}
	c.GoferPid.Store(pid)
	if got := c.liveGoferPid(); got != 0 {
		t.Errorf("liveGoferPid() for a reaped gofer = %d, want 0", got)
	}
}
