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
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/pool"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

func newTestSharedContext(t *testing.T) *sharedContext {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestStuckSubprocessHelper")
	cmd.Env = append(os.Environ(), "GVISOR_STUCK_SUBPROCESS_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start helper subprocess: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	threadID := uint32(1)
	child := &thread{tgid: int32(cmd.Process.Pid), tid: int32(cmd.Process.Pid)}
	queue := &contextQueue{}
	queue.init()
	atomic.AddUint32(&queue.end, 1)
	s := &subprocess{
		contextQueue: queue,
		syscallThread: &syscallThread{
			thread: child,
		},
		sysmsgThreads: map[uint32]*sysmsgThread{
			threadID: {thread: child},
		},
	}
	s.syscallThread.subproc = s
	shared := &sysmsg.ThreadContext{}
	shared.Init(threadID)
	atomic.StoreUint64(&shared.AckedTime, 1)
	return &sharedContext{
		subprocess: s,
		shared:     shared,
	}
}

func TestSleepOnStateStuckContext(t *testing.T) {
	sc := newTestSharedContext(t)

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 15*time.Millisecond, 10*time.Millisecond)
	if !errors.Is(err, errStuckContext) {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want %v", err, errStuckContext)
	}
}

func TestSleepOnStateStuckContextWhenStubIsGone(t *testing.T) {
	sc := newTestSharedContext(t)

	missing := &thread{tgid: 1 << 30, tid: 1 << 30}
	sc.subprocess.sysmsgThreads[1].thread = missing

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, time.Second, 10*time.Millisecond)
	if !errors.Is(err, errStubThreadGone) {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want %v", err, errStubThreadGone)
	}
}

func TestSleepOnStateRepeatedInterruptsStillStuck(t *testing.T) {
	sc := newTestSharedContext(t)

	// Interrupts are resent on every checkup wakeup. The resends must not
	// push the stuck deadline out.
	start := time.Now()
	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 30*time.Millisecond, 5*time.Millisecond)
	if !errors.Is(err, errStuckContext) {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want %v", err, errStuckContext)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("stuck context detection took %v, want under 1s", elapsed)
	}
}

func TestSleepOnStateRecoveredContext(t *testing.T) {
	sc := newTestSharedContext(t)

	stateChanged := make(chan struct{})
	go func() {
		for atomic.LoadUint32(&sc.shared.Interrupt) == 0 {
			time.Sleep(time.Millisecond)
		}
		sc.setState(sysmsg.ContextStateSyscall)
		close(stateChanged)
	}()

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 5*time.Millisecond, 10*time.Millisecond)
	<-stateChanged
	if err != nil {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want nil", err)
	}
}

// simulateHostStall makes sleepOnStateNow jump forward by stall during the
// first sleep after sc's first interrupt, as if the host stopped the whole
// sandbox during that sleep. The first returned channel is closed when that
// sleep is about to start, the second one after the clock jumped.
func simulateHostStall(t *testing.T, sc *sharedContext, stall time.Duration) (<-chan struct{}, <-chan struct{}) {
	t.Helper()
	sleeping := make(chan struct{})
	jumped := make(chan struct{})
	// After the first interrupt, sleepOnStateWithTimeout reads the clock to
	// set the checkup deadline, then before the next sleep, then after it.
	calls := 0
	sleepOnStateNow = func() time.Time {
		now := time.Now()
		if atomic.LoadUint32(&sc.shared.Interrupt) == 0 {
			return now
		}
		calls++
		switch calls {
		case 1:
			return now
		case 2:
			close(sleeping)
			return now
		case 3:
			close(jumped)
		}
		return now.Add(stall)
	}
	t.Cleanup(func() { sleepOnStateNow = time.Now })
	return sleeping, jumped
}

func TestSleepOnStateHostStallIsNotStuck(t *testing.T) {
	sc := newTestSharedContext(t)
	_, jumped := simulateHostStall(t, sc, time.Minute)

	// The stub answers shortly after the sandbox runs again.
	go func() {
		<-jumped
		time.Sleep(20 * time.Millisecond)
		sc.setState(sysmsg.ContextStateSyscall)
	}()

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 200*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want nil", err)
	}
}

func TestSleepOnStateHostStallGivesCheckupInterval(t *testing.T) {
	sc := newTestSharedContext(t)
	_, jumped := simulateHostStall(t, sc, time.Minute)

	// The stall ends after the stuck deadline. The stub must still get a
	// checkup interval to answer.
	go func() {
		<-jumped
		time.Sleep(10 * time.Millisecond)
		sc.setState(sysmsg.ContextStateSyscall)
		futexWakeUint32((*uint32)(&sc.shared.State))
	}()

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, time.Millisecond, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want nil", err)
	}
}

func TestSleepOnStateHostStallEndingInEarlyWakeup(t *testing.T) {
	sc := newTestSharedContext(t)
	sleeping, jumped := simulateHostStall(t, sc, time.Minute)

	// The stalled sleep returns early without a state change, as it does
	// when a signal interrupts it. The stub answers only after a few more
	// checkup intervals.
	go func() {
		<-sleeping
		for giveUp := time.Now().Add(time.Second); time.Now().Before(giveUp); {
			select {
			case <-jumped:
				giveUp = time.Time{}
			default:
				futexWakeUint32((*uint32)(&sc.shared.State))
				time.Sleep(100 * time.Microsecond)
			}
		}
		<-jumped
		time.Sleep(50 * time.Millisecond)
		sc.setState(sysmsg.ContextStateSyscall)
	}()

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 200*time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want nil", err)
	}
}

func TestSleepOnStateStuckAfterHostStall(t *testing.T) {
	sc := newTestSharedContext(t)
	_, jumped := simulateHostStall(t, sc, time.Minute)

	// A stub that never answers is still detected after a host stall, once
	// the time the sandbox actually ran exceeds the stuck timeout.
	start := time.Now()
	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 100*time.Millisecond, 10*time.Millisecond)
	if !errors.Is(err, errStuckContext) {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want %v", err, errStuckContext)
	}
	select {
	case <-jumped:
	default:
		t.Fatalf("sleepOnStateWithTimeout returned before the simulated host stall")
	}
	// The stall must not use up the time left before the deadline. The
	// stalled sleep can end early, so allow for one checkup interval less.
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond || elapsed > 10*time.Second {
		t.Errorf("stuck context detection took %v, want between 90ms and 10s", elapsed)
	}
}

func TestSleepOnStateDeadSubprocess(t *testing.T) {
	sc := newTestSharedContext(t)
	sc.subprocess.dead.Store(true)

	err := sc.sleepOnState(sysmsg.ContextStateNone)
	if !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("sleepOnState got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestWaitOnStateDeadSubprocess(t *testing.T) {
	sc := newTestSharedContext(t)
	sc.subprocess.dead.Store(true)

	err := sc.subprocess.waitOnState(sc)
	if !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("waitOnState got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestKickSysmsgThreadDeadSubprocess(t *testing.T) {
	sc := newTestSharedContext(t)
	sc.subprocess.dead.Store(true)

	if sc.subprocess.kickSysmsgThread() {
		t.Fatalf("kickSysmsgThread got true, want false when subprocess is dead")
	}
}

func TestWithAliveRLockDeadSubprocess(t *testing.T) {
	s := &subprocess{}
	s.dead.Store(true)

	called := false
	err := s.withAliveRLock(func() error {
		called = true
		return nil
	})
	if !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("withAliveRLock got error %v, want %v", err, errDeadSubprocess)
	}
	if called {
		t.Fatalf("withAliveRLock executed callback when dead")
	}
}

func TestSyscallDeadSubprocess(t *testing.T) {
	s := &subprocess{}
	s.dead.Store(true)

	if _, err := s.syscall(unix.SYS_MMAP); !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("syscall got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestCreateSysmsgThreadDeadSubprocess(t *testing.T) {
	s := &subprocess{}
	s.dead.Store(true)

	if err := s.createSysmsgThread(); !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("createSysmsgThread got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestReleaseDeadSubprocessDecRefs(t *testing.T) {
	sc := newTestSharedContext(t)
	s := sc.subprocess
	s.subprocessRefs.InitRefs()
	s.dead.Store(true)

	released := false
	// Set ref count to 1 and verify DecRef fires.
	s.DecRef(func() {
		released = true
	})
	if !released {
		t.Fatalf("expected subprocess to be released")
	}
}

func TestThreadWaitStoppedWhenSignaled(t *testing.T) {
	sc := newTestSharedContext(t)
	child := sc.subprocess.syscallThread.thread
	child.kill()

	_, err := child.wait(stopped)
	if !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("wait(stopped) got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestThreadWaitECHILD(t *testing.T) {
	missing := &thread{tgid: 1 << 30, tid: 1 << 30}
	_, err := missing.wait(stopped)
	if !errors.Is(err, unix.ECHILD) {
		t.Fatalf("wait(stopped) got error %v, want %v", err, unix.ECHILD)
	}
}

func TestThreadSyscallDeadThread(t *testing.T) {
	missing := &thread{tgid: 1 << 30, tid: 1 << 30}
	var regs arch.Registers
	_, err := missing.syscall(&regs)
	if !errors.Is(err, unix.ESRCH) {
		t.Fatalf("syscall got error %v, want %v", err, unix.ESRCH)
	}
}

func TestSysmsgThreadInitDeadThread(t *testing.T) {
	addr, errno := hostsyscall.RawSyscall6(
		unix.SYS_MMAP,
		0,
		hostarch.PageSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
		0, 0)
	if errno != 0 {
		t.Fatalf("mmap failed: %v", errno)
	}
	defer hostsyscall.RawSyscallErrno(unix.SYS_MUNMAP, addr, hostarch.PageSize, 0)

	st := &sysmsgThread{
		thread: &thread{tgid: 1 << 30, tid: 1 << 30},
	}
	if err := st.init(addr, addr); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("sysmsgThread.init got error %v, want %v", err, unix.ESRCH)
	}
}

func TestCreateSysmsgThreadDeadClone(t *testing.T) {
	s := &subprocess{
		requests:        make(chan any, 1),
		sysmsgStackPool: pool.Pool{Start: 0, Limit: 1},
	}
	id, ok := s.sysmsgStackPool.Get()
	if !ok {
		t.Fatalf("failed to allocate stack ID")
	}
	go func() {
		req := (<-s.requests).(requestThread)
		req.thread <- &thread{
			tgid:          1 << 30,
			tid:           1 << 30,
			sysmsgStackID: id,
		}
	}()

	if err := s.createSysmsgThread(); err == nil {
		t.Fatalf("createSysmsgThread succeeded, want error")
	}
	if _, ok := s.sysmsgStackPool.Get(); !ok {
		t.Fatalf("expected sysmsgStackID to be returned to pool on failure")
	}
}

func TestSyscallThreadKillMarksSubprocessDead(t *testing.T) {
	sc := newTestSharedContext(t)
	s := sc.subprocess

	s.syscallThread.kill()
	if !s.dead.Load() {
		t.Fatalf("expected subprocess to be marked dead after syscallThread.kill()")
	}
	if err := s.createSysmsgThread(); !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("createSysmsgThread got error %v, want %v", err, errDeadSubprocess)
	}
	req := requestThread{thread: make(chan *thread, 1)}
	s.handlePtraceSyscallRequest(req)
	if got := <-req.thread; got != nil {
		t.Fatalf("handlePtraceSyscallRequest got %v, want nil when subprocess is dead", got)
	}
}

func TestInitSyscallThreadPoolExhausted(t *testing.T) {
	s := &subprocess{
		sysmsgStackPool: pool.Pool{Start: 0, Limit: 0},
	}
	p := &thread{tgid: 1 << 30, tid: 1 << 30}
	if err := s.initSyscallThread(p, false); err == nil {
		t.Fatalf("initSyscallThread succeeded when pool was exhausted, want error")
	}
}

func TestStuckSubprocessHelper(t *testing.T) {
	if os.Getenv("GVISOR_STUCK_SUBPROCESS_HELPER") == "" {
		return
	}
	select {}
}
