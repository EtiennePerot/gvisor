// Copyright 2018 The gVisor Authors.
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

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <list>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

int64_t clock_gettime_nsecs(clockid_t id) {
  struct timespec ts;
  TEST_PCHECK(clock_gettime(id, &ts) == 0);
  return (ts.tv_sec * 1000000000 + ts.tv_nsec);
}

// Spin on the CPU for at least ns nanoseconds, based on
// CLOCK_THREAD_CPUTIME_ID.
void spin_ns(int64_t ns) {
  int64_t start = clock_gettime_nsecs(CLOCK_THREAD_CPUTIME_ID);
  int64_t end = start + ns;

  do {
    constexpr int kLoopCount = 1000000;  // large and arbitrary
    // volatile to prevent the compiler from skipping this loop.
    for (volatile int i = 0; i < kLoopCount; i++) {
    }
  } while (clock_gettime_nsecs(CLOCK_THREAD_CPUTIME_ID) < end);
}

// Test that CLOCK_PROCESS_CPUTIME_ID is a superset of CLOCK_THREAD_CPUTIME_ID.
TEST(ClockGettime, CputimeId) {
  constexpr int kNumThreads = 13;  // arbitrary

  absl::Duration spin_time = absl::Seconds(1);

  // Start off the worker threads and compute the aggregate time spent by
  // the workers. Note that we test CLOCK_PROCESS_CPUTIME_ID by having the
  // workers execute in parallel and verifying that CLOCK_PROCESS_CPUTIME_ID
  // accumulates the runtime of all threads.
  int64_t start = clock_gettime_nsecs(CLOCK_PROCESS_CPUTIME_ID);

  // Create a kNumThreads threads.
  std::list<ScopedThread> threads;
  for (int i = 0; i < kNumThreads; i++) {
    threads.emplace_back(
        [spin_time] { spin_ns(absl::ToInt64Nanoseconds(spin_time)); });
  }
  for (auto& t : threads) {
    t.Join();
  }

  int64_t end = clock_gettime_nsecs(CLOCK_PROCESS_CPUTIME_ID);

  // The aggregate time spent in the worker threads must be at least
  // 'kNumThreads' times the time each thread spun.
  ASSERT_GE(end - start, kNumThreads * absl::ToInt64Nanoseconds(spin_time));
}

TEST(ClockGettime, JavaThreadTime) {
  clockid_t clockid;
  ASSERT_EQ(0, pthread_getcpuclockid(pthread_self(), &clockid));
  struct timespec tp;
  ASSERT_THAT(clock_getres(clockid, &tp), SyscallSucceeds());
  EXPECT_TRUE(tp.tv_sec > 0 || tp.tv_nsec > 0);
  // A thread cputime is updated each 10msec and there is no approximation
  // if a task is running.
  do {
    ASSERT_THAT(clock_gettime(clockid, &tp), SyscallSucceeds());
  } while (tp.tv_sec == 0 && tp.tv_nsec == 0);
  EXPECT_TRUE(tp.tv_sec > 0 || tp.tv_nsec > 0);
}

// There is not much to test here, since CLOCK_REALTIME may be discontiguous.
TEST(ClockGettime, RealtimeWorks) {
  struct timespec tp;
  EXPECT_THAT(clock_gettime(CLOCK_REALTIME, &tp), SyscallSucceeds());
}

class MonotonicClockTest : public ::testing::TestWithParam<clockid_t> {};

TEST_P(MonotonicClockTest, IsMonotonic) {
  auto end = absl::Now() + absl::Seconds(5);

  struct timespec tp;
  EXPECT_THAT(clock_gettime(GetParam(), &tp), SyscallSucceeds());

  auto prev = absl::TimeFromTimespec(tp);
  while (absl::Now() < end) {
    EXPECT_THAT(clock_gettime(GetParam(), &tp), SyscallSucceeds());
    auto now = absl::TimeFromTimespec(tp);
    EXPECT_GE(now, prev);
    prev = now;
  }
}

std::string PrintClockId(::testing::TestParamInfo<clockid_t> info) {
  switch (info.param) {
    case CLOCK_MONOTONIC:
      return "CLOCK_MONOTONIC";
    case CLOCK_MONOTONIC_COARSE:
      return "CLOCK_MONOTONIC_COARSE";
    case CLOCK_MONOTONIC_RAW:
      return "CLOCK_MONOTONIC_RAW";
    case CLOCK_BOOTTIME:
      // CLOCK_BOOTTIME is a monotonic clock.
      return "CLOCK_BOOTTIME";
    default:
      return absl::StrCat(info.param);
  }
}

INSTANTIATE_TEST_SUITE_P(ClockGettime, MonotonicClockTest,
                         ::testing::Values(CLOCK_MONOTONIC,
                                           CLOCK_MONOTONIC_COARSE,
                                           CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME),
                         PrintClockId);

TEST(ClockGettime, UnimplementedReturnsEINVAL) {
  SKIP_IF(!IsRunningOnGvisor());

  struct timespec tp;
  EXPECT_THAT(clock_gettime(CLOCK_REALTIME_ALARM, &tp),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(clock_gettime(CLOCK_BOOTTIME_ALARM, &tp),
              SyscallFailsWithErrno(EINVAL));
}

TEST(ClockGettime, InvalidClockIDReturnsEINVAL) {
  struct timespec tp;
  EXPECT_THAT(clock_gettime(-1, &tp), SyscallFailsWithErrno(EINVAL));
}

// RawClockGettime invokes clock_gettime(2) using syscall(3), bypassing the
// vDSO. It returns 0 or -errno.
long RawClockGettime(clockid_t id, struct timespec* ts) {
  long ret = syscall(SYS_clock_gettime, id, ts);
  return ret == 0 ? 0 : -errno;
}

// SiteClockGettime invokes clock_gettime(2) from a single "mov $sysno, %eax;
// syscall" instruction sequence, like the vDSO's fallback path does. Unlike
// RawClockGettime, gVisor's systrap platform may patch this call site. It
// returns 0 or -errno.
__attribute__((noinline)) long SiteClockGettime(clockid_t id,
                                                struct timespec* ts) {
#ifdef __x86_64__
  long ret;
  asm volatile(
      "movl %[sysno], %%eax\n"
      "syscall\n"
      : "=a"(ret)
      : [sysno] "i"(SYS_clock_gettime), "D"(id), "S"(ts)
      : "rcx", "r11", "memory");
  return ret;
#else
  return RawClockGettime(id, ts);
#endif
}

using ClockGettimeFn = long (*)(clockid_t, struct timespec*);

class ThreadCputimeTest : public ::testing::TestWithParam<ClockGettimeFn> {};

int64_t ToNanoseconds(const struct timespec& ts) {
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

// Test that unwritable buffers result in EFAULT.
TEST_P(ThreadCputimeTest, BadAddressReturnsEFAULT) {
  ClockGettimeFn fn = GetParam();
  // Read the clock once, which may enable faster paths.
  struct timespec ts;
  ASSERT_EQ(fn(CLOCK_THREAD_CPUTIME_ID, &ts), 0);

  EXPECT_EQ(fn(CLOCK_THREAD_CPUTIME_ID, reinterpret_cast<struct timespec*>(8)),
            -EFAULT);

  const size_t page_size = kPageSize;
  Mapping ro = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(page_size, PROT_READ, MAP_PRIVATE));
  EXPECT_EQ(fn(CLOCK_THREAD_CPUTIME_ID, static_cast<struct timespec*>(ro.ptr())), -EFAULT);

  // The second half of the timespec is in an unmapped page.
  Mapping two = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(2 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  ASSERT_THAT(munmap(reinterpret_cast<char*>(two.addr()) + page_size,
                     page_size),
              SyscallSucceeds());
  EXPECT_EQ(fn(CLOCK_THREAD_CPUTIME_ID,
               reinterpret_cast<struct timespec*>(
                   reinterpret_cast<char*>(two.addr()) + page_size -
                   sizeof(time_t))),
            -EFAULT);
}

// Test that the thread CPU clock never goes backwards, and agrees with the
// same clock read through its thread-specific clock ID.
TEST_P(ThreadCputimeTest, Consistent) {
  ClockGettimeFn fn = GetParam();
  clockid_t self_clock;
  ASSERT_EQ(0, pthread_getcpuclockid(pthread_self(), &self_clock));

  // gVisor's thread CPU clock advances in 10ms ticks; allow reading it through
  // different clock IDs to differ by up to one tick.
  constexpr int64_t kSlackNS = 10 * 1000 * 1000;
  struct timespec ts;
  ASSERT_EQ(fn(CLOCK_THREAD_CPUTIME_ID, &ts), 0);
  int64_t last = ToNanoseconds(ts);
  const int64_t end = last + 200 * 1000 * 1000;
  while (last < end) {
    ASSERT_EQ(RawClockGettime(self_clock, &ts), 0);
    const int64_t other = ToNanoseconds(ts);
    ASSERT_GE(other, last);
    ASSERT_EQ(fn(CLOCK_THREAD_CPUTIME_ID, &ts), 0);
    const int64_t now = ToNanoseconds(ts);
    ASSERT_GE(now, last);
    ASSERT_GE(now + kSlackNS, other);
    last = now;
  }
}

// RunWithClockGettimeFilter forks a child that denies clock_gettime(2) with EPERM
// using a seccomp filter installed by install(prog), and then runs fn() in the
// child. The child exits with status 0 if fn() returns true.
template <typename InstallFn, typename Fn>
void RunWithClockGettimeFilter(InstallFn install, Fn fn) {
  pid_t pid = fork();
  if (pid == 0) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_gettime, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    _exit(fn([&] { install(&prog); }) ? 0 : 1);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

// Test that a seccomp filter applies to clock_gettime(CLOCK_THREAD_CPUTIME_ID)
// after the clock was read without one.
TEST_P(ThreadCputimeTest, HonorsSeccomp) {
  ClockGettimeFn fn = GetParam();
  RunWithClockGettimeFilter(
      [](struct sock_fprog* prog) {
        TEST_PCHECK(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, prog) ==
                    0);
      },
      [fn](auto install) {
        struct timespec ts;
        for (int i = 0; i < 100; i++) {
          if (fn(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
            return false;
          }
        }
        install();
        for (int i = 0; i < 100; i++) {
          if (fn(CLOCK_THREAD_CPUTIME_ID, &ts) != -EPERM) {
            return false;
          }
        }
        return true;
      });
}

// Test that a seccomp filter installed by another thread with
// SECCOMP_FILTER_FLAG_TSYNC applies to clock_gettime(CLOCK_THREAD_CPUTIME_ID)
// in a thread that is busy reading the clock.
TEST_P(ThreadCputimeTest, HonorsSeccompTsync) {
  ClockGettimeFn fn = GetParam();
  RunWithClockGettimeFilter(
      [](struct sock_fprog* prog) {
        TEST_PCHECK(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_TSYNC, prog) == 0);
      },
      [fn](auto install) {
        std::atomic<bool> installed(false);
        std::atomic<int64_t> reads(0);
        std::atomic<bool> ok(true);
        pthread_t thread;
        struct Args {
          ClockGettimeFn fn;
          std::atomic<bool>* installed;
          std::atomic<int64_t>* reads;
          std::atomic<bool>* ok;
        } args = {fn, &installed, &reads, &ok};
        TEST_PCHECK(pthread_create(
                        &thread, nullptr,
                        +[](void* arg) -> void* {
                          Args* a = static_cast<Args*>(arg);
                          struct timespec ts;
                          for (;;) {
                            bool installed = a->installed->load();
                            long ret = a->fn(CLOCK_THREAD_CPUTIME_ID, &ts);
                            if (installed) {
                              if (ret != -EPERM) {
                                a->ok->store(false);
                              }
                              return nullptr;
                            }
                            // The filter may take effect before installed
                            // is set.
                            if (ret != 0 && ret != -EPERM) {
                              a->ok->store(false);
                              return nullptr;
                            }
                            a->reads->fetch_add(1);
                          }
                        },
                        &args) == 0);
        while (reads.load() < 1000 && ok.load()) {
          sched_yield();
        }
        install();
        installed.store(true);
        TEST_PCHECK(pthread_join(thread, nullptr) == 0);
        return ok.load();
      });
}

// Outcomes of a clock_gettime call in a child process, as exit codes.
constexpr int kOutcomeSuccess = 10;
constexpr int kOutcomeEPERM = 11;
constexpr int kOutcomeENOSYS = 12;
constexpr int kOutcomeTrapped = 13;
constexpr int kOutcomeOther = 14;

std::atomic<int> sigsys_count(0);

// Test that clock_gettime(CLOCK_THREAD_CPUTIME_ID) gets the result of every
// seccomp filter action, after the clock was read without a filter.
TEST_P(ThreadCputimeTest, SeccompActions) {
  ClockGettimeFn fn = GetParam();
  struct Case {
    const char* name;
    uint32_t action;
    // If true, the filter only applies the action if the first argument is
    // CLOCK_THREAD_CPUTIME_ID.
    bool check_arg;
    // Expected outcome (if not killed).
    int outcome;
    // Expected outcome if killed: whether the child is killed by SIGSYS.
    bool killed;
    // Alternative accepted outcome, if any.
    int alt_outcome;
  };
  const Case cases[] = {
      {"ALLOW", SECCOMP_RET_ALLOW, false, kOutcomeSuccess, false, 0},
      {"LOG", SECCOMP_RET_LOG, false, kOutcomeSuccess, false, 0},
      {"ERRNO", SECCOMP_RET_ERRNO | EPERM, false, kOutcomeEPERM, false, 0},
      {"ERRNO for this clock", SECCOMP_RET_ERRNO | EPERM, true, kOutcomeEPERM,
       false, 0},
      {"TRAP", SECCOMP_RET_TRAP, false, kOutcomeTrapped, false, 0},
      // Without a tracer, SECCOMP_RET_TRACE fails the syscall with ENOSYS.
      {"TRACE", SECCOMP_RET_TRACE, false, kOutcomeENOSYS, false, 0},
      {"KILL_THREAD", SECCOMP_RET_KILL_THREAD, false, 0, true, 0},
      {"KILL_PROCESS", SECCOMP_RET_KILL_PROCESS, false, 0, true, 0},
      // Without a listener, Linux fails the syscall with ENOSYS, while gVisor
      // kills the thread.
      {"USER_NOTIF", SECCOMP_RET_USER_NOTIF, false, kOutcomeENOSYS,
       IsRunningOnGvisor(), 0},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(c.name);
    pid_t pid = fork();
    if (pid == 0) {
      struct sock_filter filter[] = {
          BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
          BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_gettime, 0, 3),
          BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                   offsetof(struct seccomp_data, args[0])),
          BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CLOCK_THREAD_CPUTIME_ID, 0, 1),
          BPF_STMT(BPF_RET | BPF_K, c.action),
          BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      };
      if (!c.check_arg) {
        // Skip the argument check.
        filter[1] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_gettime, 2, 3);
      }
      struct sock_fprog prog = {
          .len = sizeof(filter) / sizeof(filter[0]),
          .filter = filter,
      };
      struct sigaction sa = {};
      sa.sa_handler = +[](int) { sigsys_count.fetch_add(1); };
      TEST_PCHECK(sigaction(SIGSYS, &sa, nullptr) == 0);
      struct timespec ts;
      for (int i = 0; i < 100; i++) {
        TEST_PCHECK(fn(CLOCK_THREAD_CPUTIME_ID, &ts) == 0);
      }
      TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
      TEST_PCHECK(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) ==
                  0);
      long ret = fn(CLOCK_THREAD_CPUTIME_ID, &ts);
      if (sigsys_count.load() != 0) {
        _exit(kOutcomeTrapped);
      }
      switch (ret) {
        case 0:
          _exit(kOutcomeSuccess);
        case -EPERM:
          _exit(kOutcomeEPERM);
        case -ENOSYS:
          _exit(kOutcomeENOSYS);
        default:
          _exit(kOutcomeOther);
      }
    }
    ASSERT_THAT(pid, SyscallSucceeds());
    int status;
    ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
                SyscallSucceedsWithValue(pid));
    if (c.killed) {
      EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
          << "status " << status;
    } else {
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == c.outcome)
          << "status " << status;
    }
  }
}

// Test that new processes and threads start with a zero thread CPU clock, and
// don't see the clock of their parent or of a thread that exited.
TEST_P(ThreadCputimeTest, NewThreadsStartFromZero) {
  ClockGettimeFn fn = GetParam();
  constexpr int64_t kSpinNS = 200 * 1000 * 1000;
  // A new thread must have used much less CPU time than this when it first
  // reads its clock.
  constexpr int64_t kMaxInitialNS = kSpinNS / 2;
  auto spin = [fn] {
    struct timespec ts;
    do {
      TEST_PCHECK(fn(CLOCK_THREAD_CPUTIME_ID, &ts) == 0);
    } while (ToNanoseconds(ts) < kSpinNS);
  };
  auto initial = [fn] {
    struct timespec ts;
    TEST_PCHECK(fn(CLOCK_THREAD_CPUTIME_ID, &ts) == 0);
    return ToNanoseconds(ts);
  };

  spin();
  pid_t pid = fork();
  if (pid == 0) {
    _exit(initial() < kMaxInitialNS ? 0 : 1);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;

  int64_t first;
  ScopedThread([&] { first = initial(); }).Join();
  EXPECT_LT(first, kMaxInitialNS);

  for (int i = 0; i < 3; i++) {
    ScopedThread(spin).Join();
    ScopedThread([&] { first = initial(); }).Join();
    EXPECT_LT(first, kMaxInitialNS);
  }
}

// Test that the thread CPU clock is monotonic while the thread moves between
// CPUs.
TEST_P(ThreadCputimeTest, MonotonicAcrossCPUs) {
  ClockGettimeFn fn = GetParam();
  cpu_set_t orig;
  ASSERT_THAT(sched_getaffinity(0, sizeof(orig), &orig), SyscallSucceeds());
  int64_t last = 0;
  for (int round = 0; round < 3; round++) {
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
      if (!CPU_ISSET(cpu, &orig)) {
        continue;
      }
      cpu_set_t set;
      CPU_ZERO(&set);
      CPU_SET(cpu, &set);
      ASSERT_THAT(sched_setaffinity(0, sizeof(set), &set), SyscallSucceeds());
      for (int i = 0; i < 1000; i++) {
        struct timespec ts;
        ASSERT_EQ(fn(CLOCK_THREAD_CPUTIME_ID, &ts), 0);
        ASSERT_GE(ToNanoseconds(ts), last);
        last = ToNanoseconds(ts);
      }
    }
  }
  ASSERT_THAT(sched_setaffinity(0, sizeof(orig), &orig), SyscallSucceeds());
}

constexpr char kExecMinEnv[] = "CLOCK_GETTIME_TEST_EXEC_MIN_NS";
constexpr int kExecHelperOK = 42;

// Test that the thread CPU clock keeps its value across execve.
TEST_P(ThreadCputimeTest, ContinuesAcrossExec) {
  ClockGettimeFn fn = GetParam();
  pid_t pid = fork();
  if (pid == 0) {
    struct timespec ts;
    do {
      TEST_PCHECK(fn(CLOCK_THREAD_CPUTIME_ID, &ts) == 0);
    } while (ToNanoseconds(ts) < 100 * 1000 * 1000);
    std::string env = absl::StrCat(kExecMinEnv, "=", ToNanoseconds(ts));
    char* const argv[] = {
        const_cast<char*>("clock_gettime_test"),
        const_cast<char*>(
            "--gtest_filter=ClockGettimeExecHelper.ThreadCputimeAfterExec"),
        nullptr};
    char* const envp[] = {const_cast<char*>(env.c_str()), nullptr};
    execve("/proc/self/exe", argv, envp);
    _exit(1);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExecHelperOK)
      << "status " << status;
}

// Helper for ContinuesAcrossExec, run after execve. Exits with kExecHelperOK
// if the thread CPU clock didn't go backwards across execve.
TEST(ClockGettimeExecHelper, ThreadCputimeAfterExec) {
  const char* min_env = getenv(kExecMinEnv);
  if (min_env == nullptr) {
    GTEST_SKIP() << "Only run by ContinuesAcrossExec";
  }
  int64_t min_ns;
  ASSERT_TRUE(absl::SimpleAtoi(min_env, &min_ns));
  for (ClockGettimeFn fn : {RawClockGettime, SiteClockGettime}) {
    struct timespec ts;
    TEST_CHECK(fn(CLOCK_THREAD_CPUTIME_ID, &ts) == 0);
    TEST_CHECK(ToNanoseconds(ts) >= min_ns);
  }
  _exit(kExecHelperOK);
}

INSTANTIATE_TEST_SUITE_P(ClockGettime, ThreadCputimeTest,
                         ::testing::Values(RawClockGettime, SiteClockGettime));

}  // namespace

}  // namespace testing
}  // namespace gvisor
