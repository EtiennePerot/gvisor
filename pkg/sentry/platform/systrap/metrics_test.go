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

package systrap

import (
	"reflect"
	"testing"
)

const testPeriod = 1000

// newTestFastPathState returns a fastPathState whose state machine only counts
// its runs, and sets recordingPeriodTicks to testPeriod for the duration of
// the test.
func newTestFastPathState(t *testing.T, runs *int) *fastPathState {
	t.Helper()
	old := recordingPeriodTicks
	recordingPeriodTicks = testPeriod
	t.Cleanup(func() { recordingPeriodTicks = old })
	s := &fastPathState{}
	s.curState = func(*fastPathState) { *runs++ }
	return s
}

func isState(got, want func(*fastPathState)) bool {
	return reflect.ValueOf(got).Pointer() == reflect.ValueOf(want).Pointer()
}

func TestRecordActivityRunsStateMachineOncePerPeriod(t *testing.T) {
	var runs int
	s := newTestFastPathState(t, &runs)
	s.lastEval.Store(10 * testPeriod)
	for _, tc := range []struct {
		now  int64
		runs int
	}{
		{now: 10*testPeriod - 1, runs: 0}, // before lastEval, e.g. a stale timestamp
		{now: 10 * testPeriod, runs: 0},
		{now: 11*testPeriod - 1, runs: 0},
		{now: 11 * testPeriod, runs: 1},
		{now: 11*testPeriod + 1, runs: 1},
		{now: 12*testPeriod - 1, runs: 1},
		{now: 12*testPeriod + testPeriod/2, runs: 2},
		{now: 13*testPeriod + testPeriod/2 - 1, runs: 2},
		{now: 13*testPeriod + testPeriod/2, runs: 3},
	} {
		s.recordActivity(tc.now)
		if runs != tc.runs {
			t.Fatalf("after recordActivity(%d): state machine ran %d times, want %d", tc.now, runs, tc.runs)
		}
	}
	if got, want := s.lastEval.Load(), int64(13*testPeriod+testPeriod/2); got != want {
		t.Errorf("lastEval = %d, want %d", got, want)
	}
}

func TestRecordActivitySkipsWhileEvaluating(t *testing.T) {
	var runs int
	s := newTestFastPathState(t, &runs)
	s.lastEval.Store(testPeriod)

	s.evalMu.Lock()
	s.recordActivity(2 * testPeriod)
	s.evalMu.Unlock()
	if runs != 0 {
		t.Fatalf("state machine ran %d times while evalMu was held, want 0", runs)
	}
	if got := s.lastEval.Load(); got != testPeriod {
		t.Fatalf("lastEval = %d while evalMu was held, want %d", got, testPeriod)
	}

	s.recordActivity(2 * testPeriod)
	if runs != 1 {
		t.Fatalf("state machine ran %d times after evalMu was released, want 1", runs)
	}
}

func TestRecordActivityResetsTrackers(t *testing.T) {
	var runs int
	s := newTestFastPathState(t, &runs)
	s.lastEval.Store(testPeriod)
	s.usedStubFastPath.Store(true)
	s.usedSentryFastPath.Store(true)

	// The state machine must see the trackers of the period being evaluated.
	s.curState = func(s *fastPathState) {
		runs++
		if !s.usedStubFastPath.Load() || !s.usedSentryFastPath.Load() {
			t.Errorf("trackers reset before the state machine ran")
		}
	}
	s.recordActivity(2 * testPeriod)
	if runs != 1 {
		t.Fatalf("state machine ran %d times, want 1", runs)
	}
	if s.usedStubFastPath.Load() || s.usedSentryFastPath.Load() {
		t.Errorf("trackers not reset after evaluation: usedStubFastPath=%t usedSentryFastPath=%t",
			s.usedStubFastPath.Load(), s.usedSentryFastPath.Load())
	}
}

func TestRecordActivityIdle(t *testing.T) {
	for _, tc := range []struct {
		name    string
		elapsed int64
		idle    bool
	}{
		{name: "one period", elapsed: testPeriod, idle: false},
		{name: "just under two periods", elapsed: 2*testPeriod - 1, idle: false},
		{name: "two periods", elapsed: 2 * testPeriod, idle: true},
		{name: "long gap", elapsed: 1000 * testPeriod, idle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var runs int
			s := newTestFastPathState(t, &runs)
			counting := s.curState
			s.lastEval.Store(testPeriod)
			s.stubFastPathEnabled.Store(true)
			s.sentryFastPathEnabled.Store(true)
			s.stubFPBackoff = 3
			s.sentryFPRecentFailures = 4

			s.recordActivity(testPeriod + tc.elapsed)

			// Samples collected before the gap are still evaluated.
			if runs != 1 {
				t.Errorf("state machine ran %d times, want 1", runs)
			}
			if got := s.stubFastPathEnabled.Load(); got == tc.idle {
				t.Errorf("stubFastPathEnabled = %t, want %t", got, !tc.idle)
			}
			if got := s.sentryFastPathEnabled.Load(); got == tc.idle {
				t.Errorf("sentryFastPathEnabled = %t, want %t", got, !tc.idle)
			}
			if tc.idle && !isState(s.curState, sentryOffStubOff) {
				t.Errorf("curState is not sentryOffStubOff after an idle period")
			}
			if !tc.idle && !isState(s.curState, counting) {
				t.Errorf("curState changed without an idle period")
			}
			// Idleness is not a fast path failure.
			if s.stubFPBackoff != 3 || s.sentryFPRecentFailures != 4 {
				t.Errorf("idle changed backoff state: stubFPBackoff=%d sentryFPRecentFailures=%d, want 3 and 4",
					s.stubFPBackoff, s.sentryFPRecentFailures)
			}
		})
	}
}

func BenchmarkRecordActivity(b *testing.B) {
	old := recordingPeriodTicks
	recordingPeriodTicks = testPeriod
	b.Cleanup(func() { recordingPeriodTicks = old })
	for _, bc := range []struct {
		name  string
		every int64
	}{
		{name: "NoEvaluation", every: 0},
		{name: "Evaluation", every: testPeriod},
	} {
		b.Run(bc.name, func(b *testing.B) {
			s := &fastPathState{curState: sentryOnStubOn}
			s.stubFastPathEnabled.Store(true)
			s.sentryFastPathEnabled.Store(true)
			for i := 0; i < numLatencyBuckets; i++ {
				s.stubBoundBaselineLatency[i].Store(10)
				s.sentryBoundBaselineLatency[i].Store(10)
			}
			now := int64(testPeriod)
			for i := 0; i < b.N; i++ {
				for j := 0; j < minNecessaryRecordings; j++ {
					latencies.stubBound.record(cpuTicks(j * bucketIncrements))
					latencies.sentryBound.record(cpuTicks(j * bucketIncrements))
				}
				now += bc.every
				s.recordActivity(now)
			}
		})
	}
}
