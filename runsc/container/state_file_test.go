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

	"golang.org/x/sys/unix"
)

type testState struct {
	Status  string `json:"status"`
	Padding string `json:"padding"`
}

func newTestStateFile(t *testing.T) *StateFile {
	t.Helper()
	s := &StateFile{
		RootDir: t.TempDir(),
		ID:      FullID{SandboxID: "sandbox", ContainerID: "container"},
	}
	t.Cleanup(func() { _ = s.close() })
	return s
}

func saveTestState(t *testing.T, s *StateFile, v testState) error {
	t.Helper()
	if err := s.lock(BlockAcquire); err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer s.UnlockOrDie()
	return s.SaveLocked(v)
}

func loadTestState(t *testing.T, s *StateFile) testState {
	t.Helper()
	other := StateFile{RootDir: s.RootDir, ID: s.ID}
	defer other.close()
	var v testState
	if err := other.load(&v, LoadOpts{}); err != nil {
		t.Fatalf("load: %v", err)
	}
	return v
}

func checkListed(t *testing.T, s *StateFile) {
	t.Helper()
	ids, err := List(s.RootDir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 || ids[0] != s.ID {
		t.Errorf("List = %v, want [%v]", ids, s.ID)
	}
}

// TestSaveFailureKeepsPreviousState checks that a failed save, e.g. because
// the disk is full, leaves the previous state file in place.
func TestSaveFailureKeepsPreviousState(t *testing.T) {
	s := newTestStateFile(t)
	created := testState{Status: "created", Padding: strings.Repeat("x", 4096)}
	if err := saveTestState(t, s, created); err != nil {
		t.Fatalf("SaveLocked: %v", err)
	}

	// Write half of the data, then fail like a full disk would.
	defer func(orig func(string, []byte, os.FileMode) error) { writeFile = orig }(writeFile)
	writeFile = func(path string, data []byte, perm os.FileMode) error {
		if err := os.WriteFile(path, data[:len(data)/2], perm); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return unix.ENOSPC
	}
	if err := saveTestState(t, s, testState{Status: "running"}); err == nil {
		t.Fatalf("SaveLocked succeeded, want error")
	}
	if got := loadTestState(t, s); got != created {
		t.Errorf("state after failed save: got status %q, want %q", got.Status, created.Status)
	}
	if _, err := os.Stat(s.tmpStatePath()); !os.IsNotExist(err) {
		t.Errorf("temporary state file left after failed save: %v", err)
	}
	checkListed(t, s)

	writeFile = os.WriteFile
	running := testState{Status: "running"}
	if err := saveTestState(t, s, running); err != nil {
		t.Fatalf("SaveLocked: %v", err)
	}
	if got := loadTestState(t, s); got != running {
		t.Errorf("state after save: got status %q, want %q", got.Status, running.Status)
	}
	fi, err := s.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&^0640 != 0 {
		t.Errorf("state file mode = %v, want at most 0640", perm)
	}
}

// TestLeftoverTemporaryFile checks that a temporary state file left by a
// writer that died before renaming it is ignored, overwritten by the next save
// and removed by Destroy.
func TestLeftoverTemporaryFile(t *testing.T) {
	s := newTestStateFile(t)
	if err := saveTestState(t, s, testState{Status: "created"}); err != nil {
		t.Fatalf("SaveLocked: %v", err)
	}
	if err := os.WriteFile(s.tmpStatePath(), []byte(`{"status":"runn`), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	checkListed(t, s)
	if got := loadTestState(t, s); got.Status != "created" {
		t.Errorf("state with leftover temporary file: got status %q, want %q", got.Status, "created")
	}

	if err := saveTestState(t, s, testState{Status: "running"}); err != nil {
		t.Fatalf("SaveLocked: %v", err)
	}
	if got := loadTestState(t, s); got.Status != "running" {
		t.Errorf("state after save: got status %q, want %q", got.Status, "running")
	}

	if err := os.WriteFile(s.tmpStatePath(), []byte(`{"status":"runn`), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := s.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	entries, err := os.ReadDir(s.RootDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		t.Errorf("file left after Destroy: %q", e.Name())
	}
}

// TestUnlockedReadersSeeCompleteState checks that readers that don't take the
// lock (e.g. Stat users, or processes reading the state of other containers)
// never see a partially written state file.
func TestUnlockedReadersSeeCompleteState(t *testing.T) {
	s := newTestStateFile(t)
	states := []testState{
		{Status: "created", Padding: strings.Repeat("x", 64<<10)},
		{Status: "running", Padding: strings.Repeat("y", 32<<10)},
	}
	if err := saveTestState(t, s, states[0]); err != nil {
		t.Fatalf("SaveLocked: %v", err)
	}

	done := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		for {
			select {
			case <-done:
				return
			default:
			}
			data, err := os.ReadFile(s.statePath())
			if err != nil {
				errs <- err
				return
			}
			var v testState
			if err := json.Unmarshal(data, &v); err != nil {
				errs <- err
				return
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		if err := saveTestState(t, s, states[i%2]); err != nil {
			t.Fatalf("SaveLocked: %v", err)
		}
	}
	close(done)
	if err := <-errs; err != nil {
		t.Errorf("unlocked reader saw an incomplete state file: %v", err)
	}
}
