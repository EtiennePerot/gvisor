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

package platforms

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// TestHostSetupMatchesConstructor checks that each registered platform's
// HostSetup agrees with its Constructor.
func TestHostSetupMatchesConstructor(t *testing.T) {
	for _, name := range platform.List() {
		c, err := platform.Lookup(name)
		if err != nil {
			t.Fatalf("platform.Lookup(%q): %v", name, err)
		}
		h, err := platform.LookupHostSetup(name)
		if err != nil {
			t.Errorf("platform.LookupHostSetup(%q): %v", name, err)
			continue
		}
		if got, want := h.Requirements(), c.Requirements(); got != want {
			t.Errorf("platform %q: HostSetup requirements %+v, Constructor requirements %+v", name, got, want)
		}
	}
}
