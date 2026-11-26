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

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(LandlockV1Test, AbiVersionIsSupported) {
  int version = LandlockAbiVersion();
  SKIP_IF(version < 0 && errno == ENOSYS);
  ASSERT_GE(version, 1) << "unexpected Landlock ABI version";
}

TEST(LandlockV1Test, CreateRulesetSizeHandling) {
  SKIP_IF(LandlockAbiVersion() < 1);
  uint64_t fs_only = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(
                  reinterpret_cast<landlock_ruleset_attr*>(&fs_only), 7, 0),
              SyscallFailsWithErrno(EINVAL));
  int fd = landlock_create_ruleset(
      reinterpret_cast<landlock_ruleset_attr*>(&fs_only), sizeof(fs_only), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
  const long page_size = sysconf(_SC_PAGESIZE);
  std::vector<char> big(page_size + 8, 0);
  memcpy(big.data(), &fs_only, sizeof(fs_only));
  EXPECT_THAT(
      landlock_create_ruleset(
          reinterpret_cast<landlock_ruleset_attr*>(big.data()), big.size(), 0),
      SyscallFailsWithErrno(E2BIG));
  std::vector<char> tail(sizeof(landlock_ruleset_attr) + 8, 0);
  memcpy(tail.data(), &fs_only, sizeof(fs_only));
  tail[tail.size() - 1] = 1;
  int rc = landlock_create_ruleset(
      reinterpret_cast<landlock_ruleset_attr*>(tail.data()), tail.size(), 0);
  EXPECT_LT(rc, 0);
  EXPECT_THAT(errno, ::testing::AnyOf(E2BIG, EINVAL));
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
  landlock_ruleset_attr full = {};
  full.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  full.scoped = (1ULL << 63);
  rc = landlock_create_ruleset(&full, sizeof(full), 0);
  EXPECT_LT(rc, 0);
  EXPECT_THAT(errno, ::testing::AnyOf(E2BIG, EINVAL));
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
}

TEST(LandlockV1Test, CreateRulesetNullAttrReturnsEfault) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(landlock_create_ruleset(nullptr, 0, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(landlock_create_ruleset(nullptr, 7, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(
      landlock_create_ruleset(nullptr, sizeof(landlock_ruleset_attr), 0),
      SyscallFailsWithErrno(EFAULT));
}

TEST(LandlockV1Test, CreateRulesetEmptyHandledAccessReturnsEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(ENOMSG));
}

TEST(LandlockV1Test, CreateRulesetErrataReturnsBitmask) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int rc = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_ERRATA);
  if (rc < 0) {
    EXPECT_EQ(errno, EINVAL) << "unexpected errno " << errno;
  } else {
    EXPECT_GE(rc, 0);
  }
}

TEST(LandlockV1Test, CreateRulesetErrataRejectsAttr) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_REG;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr),
                                      LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(landlock_create_ruleset(nullptr, sizeof(attr),
                                      LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, CreateRulesetVersionAndErrataRejected) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(landlock_create_ruleset(nullptr, 0,
                                      LANDLOCK_CREATE_RULESET_VERSION |
                                          LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, CreateRulesetRejectsUnknownFlags) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0xffff),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, AddRuleRejectsUnknownRuleType) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(fd, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EINVAL));
  close(fd);
}

TEST(LandlockV1Test, AddRuleBadFdWithBadRuleTypeReportsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(-1, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADF));

  int file_fd = open("/", O_RDONLY | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());
  EXPECT_THAT(
      landlock_add_rule(file_fd, static_cast<landlock_rule_type>(0xffff),
                        &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(file_fd);
}

TEST(LandlockV1Test, OPathRulesetFdIsEbadf) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int opath_fd = open(dir.path().c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
  ASSERT_THAT(opath_fd, SyscallSucceeds());
  auto close_opath = Cleanup([opath_fd] { close(opath_fd); });
  int parent_fd = open(dir.path().c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  auto close_parent = Cleanup([parent_fd] { close(parent_fd); });
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(opath_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADF));
  int plain_fd = open(dir.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  ASSERT_THAT(plain_fd, SyscallSucceeds());
  auto close_plain = Cleanup([plain_fd] { close(plain_fd); });
  EXPECT_THAT(
      landlock_add_rule(plain_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));

  constexpr int kBadf = 130;
  constexpr int kBadfd = 131;
  static std::string path;
  path = dir.path();
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    int fd = open(path.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (landlock_restrict_self(fd, 0) == 0) {
      _exit(kAllowed);
    }
    switch (errno) {
      case EBADF:
        _exit(kBadf);
      case EBADFD:
        _exit(kBadfd);
      default:
        _exit(kOther);
    }
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kBadf)
      << "exit status " << status;
}

TEST(LandlockV1Test, AddRuleNullAttrReturnsEfault) {
  SKIP_IF(LandlockAbiVersion() < 1);

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  EXPECT_THAT(
      landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, nullptr, 0),
      SyscallFailsWithErrno(EFAULT));
  close(ruleset_fd);
}

TEST(LandlockV1Test, AddRuleUnknownFlagsReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 2),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, RestrictSelfWithoutNoNewPrivsFails) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    TEST_PCHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
    TEST_PCHECK(SetCapability(CAP_SYS_ADMIN, false).ok());
    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(fd, 0) < 0 && errno == EPERM ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

TEST(LandlockV1Test, RestrictSelfChecksFlagsThenNoNewPrivsThenFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const bool flags_first = IsRunningOnGvisor() || LandlockAbiVersion() >= 11;
  AutoCapability cap_admin(CAP_SYS_ADMIN, false);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_EXECUTE);
    if (landlock_restrict_self(-1, ~0u) != -1) {
      _exit(kOther);
    }
    if (errno != EINVAL && !(errno == EPERM && !flags_first)) {
      _exit(kOther);
    }
    if (landlock_restrict_self(-1, 0) != -1 || errno != EPERM) {
      _exit(kOther);
    }
    if (landlock_restrict_self(fd, 0) != -1 || errno != EPERM) {
      _exit(kOther);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    if (landlock_restrict_self(-1, ~0u) != -1 || errno != EINVAL) {
      _exit(kOther);
    }
    if (landlock_restrict_self(-1, 0) != -1 || errno != EBADF) {
      _exit(kOther);
    }
    if (landlock_restrict_self(fd, 0) != 0) {
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictSelfUnknownFlagsWithNoNewPrivsReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(fd, 1u << 31) < 0 && errno == EINVAL ? kDenied
                                                                      : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictSelfRejectsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(-1, 0) < 0 && errno == EBADF ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

TEST(LandlockV1Test, RulesetFdRejectsIO) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  char c;
  EXPECT_THAT(read(fd, &c, 1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(write(fd, &c, 1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(lseek(fd, 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  close(fd);
}

TEST(LandlockV1Test, RulesetFdIsCloseOnExecAndReadWrite) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  FileDescriptor fd(landlock_create_ruleset(&attr, sizeof(attr), 0));
  ASSERT_THAT(fd.get(), SyscallSucceeds());
  // Close-on-exec is a descriptor flag; the file description's status flags
  // hold only the access mode.
  EXPECT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
  EXPECT_THAT(fcntl(fd.get(), F_GETFL), SyscallSucceedsWithValue(O_RDWR));
}

TEST(LandlockV1Test, CreateRulesetHandlingAllV1RightsSucceeds) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
}

TEST(LandlockV1Test, CreateRulesetRejectsUnknownAccessBits) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = (1ULL << 63);
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, AddRuleEmptyAllowedAccessReturnsEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.parent_fd = -1;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(ENOMSG));
  close(fd);
}

TEST(LandlockV1Test, AddPathBeneathRejectsUnhandledAccess) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, AddRuleDirOnlyRightsOnNonDirectoryReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(file.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_DIR;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallSucceeds());
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, FileRuleAcceptsOnlyFileCompatibleRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  int file_fd = open(file.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());

  constexpr uint64_t kFileCompatible = LANDLOCK_ACCESS_FS_EXECUTE |
                                       LANDLOCK_ACCESS_FS_WRITE_FILE |
                                       LANDLOCK_ACCESS_FS_READ_FILE;
  for (int bit = 0; bit < 13; bit++) {
    const uint64_t access = 1ULL << bit;
    landlock_path_beneath_attr path_beneath = {};
    path_beneath.allowed_access = access;
    path_beneath.parent_fd = file_fd;
    if (access & kFileCompatible) {
      EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &path_beneath, 0),
                  SyscallSucceeds())
          << "access bit " << bit;
    } else {
      EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &path_beneath, 0),
                  SyscallFailsWithErrno(EINVAL))
          << "access bit " << bit;
    }
  }
  close(ruleset_fd);
  close(file_fd);
}

TEST(LandlockV1Test, AddPathBeneathRejectsInternalMountFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  auto close_ruleset = Cleanup([fd] { close(fd); });

  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;

  int memfd = syscall(SYS_memfd_create, "landlock_v1_test", 0);
  ASSERT_THAT(memfd, SyscallSucceeds());
  path_beneath.parent_fd = memfd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(memfd);

  int ns_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  if (ns_fd >= 0) {
    path_beneath.parent_fd = ns_fd;
    EXPECT_THAT(
        landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
        SyscallFailsWithErrno(EBADFD));
    close(ns_fd);
  }

  int sv[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), SyscallSucceeds());
  path_beneath.parent_fd = sv[0];
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(sv[0]);
  close(sv[1]);
}

TEST(LandlockV1Test, MaxSixteenStackedLayers) {
  SKIP_IF(LandlockAbiVersion() < 1);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    for (int i = 0; i < 16; i++) {
      int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR);
      if (landlock_restrict_self(fd, 0) != 0) {
        _exit(kSetup);
      }
      close(fd);
    }
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR);
    int rc = landlock_restrict_self(fd, 0);
    close(fd);
    _exit(rc < 0 && errno == E2BIG ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, TruncateUnrestrictedByV1Domain) {
  SKIP_IF(LandlockAbiVersion() < 1);

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "content", 0666));
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(target.c_str(), O_WRONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    if (truncate(target.c_str(), 3) != 0) {
      _exit(errno == EACCES ? kDenied : kOther);
    }
    if (ftruncate(fd, 0) != 0) {
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
