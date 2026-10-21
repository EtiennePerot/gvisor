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

package seccheck

import (
	"testing"
)

// TestCreateInitializesPoints checks that Create works without a prior call
// to Initialize. This must run in its own test binary, since other tests
// call Initialize from TestMain.
func TestCreateInitializesPoints(t *testing.T) {
	if len(Points) != 0 {
		t.Fatalf("Points registered before Create: got %d, want 0", len(Points))
	}

	const point = "syscall/openat/enter"
	conf := SessionConfig{
		Name: DefaultSessionName,
		Points: []PointConfig{
			{
				Name:           point,
				OptionalFields: []string{"fd_path"},
				ContextFields:  []string{"time"},
			},
		},
	}
	if err := Create(&conf, false); err != nil {
		t.Fatalf("Create(): %v", err)
	}
	defer func() {
		if err := Delete(conf.Name); err != nil {
			t.Errorf("Delete(%q): %v", conf.Name, err)
		}
	}()

	if _, ok := Points[point]; !ok {
		t.Errorf("point %q not registered after Create", point)
	}
}
