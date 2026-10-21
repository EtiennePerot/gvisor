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

package tests

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

// TestCollectStats checks that per-type stats are collected only if
// state.CollectStats is set.
func TestCollectStats(t *testing.T) {
	defer func(collect bool) { state.CollectStats = collect }(state.CollectStats)
	for _, collect := range []bool{false, true} {
		state.CollectStats = collect
		obj := outerFieldFirst{v: 1}
		var buf bytes.Buffer
		saveStats, err := state.Save(context.Background(), &buf, &obj)
		if err != nil {
			t.Fatalf("Save failed: %v", err)
		}
		var got outerFieldFirst
		loadStats, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &got)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		for _, s := range []struct {
			name  string
			stats state.Stats
		}{{"Save", saveStats}, {"Load", loadStats}} {
			str := s.stats.String()
			if collected := strings.Contains(str, "outerFieldFirst"); collected != collect {
				t.Errorf("CollectStats = %t: %s stats collected = %t; stats:\n%s", collect, s.name, collected, str)
			}
		}
	}
}
