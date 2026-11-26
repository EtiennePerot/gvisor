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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	// landlockABIVersion is the Landlock ABI version that
	// landlock_create_ruleset(2) reports for LANDLOCK_CREATE_RULESET_VERSION.
	landlockABIVersion = 1

	// landlockErrata is the errata bitmask that landlock_create_ruleset(2)
	// reports for LANDLOCK_CREATE_RULESET_ERRATA. Bit N-1 stands for erratum
	// N. Only erratum 3, the handling of disconnected directories, applies.
	landlockErrata = 1 << (3 - 1)

	// landlockRulesetAttrMinSize is the size of struct landlock_ruleset_attr
	// in Landlock ABI version 1: a single u64, handled_access_fs.
	landlockRulesetAttrMinSize = 8

	// landlockFileAccessFS is the set of filesystem rights that a rule on a
	// file that is not a directory may grant.
	landlockFileAccessFS = linux.LANDLOCK_ACCESS_FS_EXECUTE |
		linux.LANDLOCK_ACCESS_FS_WRITE_FILE |
		linux.LANDLOCK_ACCESS_FS_READ_FILE
)

// LandlockCreateRuleset implements Linux syscall landlock_create_ruleset(2).
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	if !t.Kernel().LandlockEnabled {
		return 0, nil, linuxerr.ENOSYS
	}
	addr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if addr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		switch flags {
		case linux.LANDLOCK_CREATE_RULESET_VERSION:
			return landlockABIVersion, nil, nil
		case linux.LANDLOCK_CREATE_RULESET_ERRATA:
			return landlockErrata, nil, nil
		default:
			return 0, nil, linuxerr.EINVAL
		}
	}

	if addr == 0 {
		return 0, nil, linuxerr.EFAULT
	}
	if size < landlockRulesetAttrMinSize {
		return 0, nil, linuxerr.EINVAL
	}
	if size > uint(hostarch.PageSize) {
		return 0, nil, linuxerr.E2BIG
	}
	// Fields of later ABI versions, such as handled_access_net, must be zero.
	// They are checked before handled_access_fs is read, so a caller that
	// sets one gets E2BIG and never ENOMSG.
	if size > landlockRulesetAttrMinSize {
		tailAddr, ok := addr.AddLength(landlockRulesetAttrMinSize)
		if !ok {
			return 0, nil, linuxerr.EFAULT
		}
		tail := make([]byte, size-landlockRulesetAttrMinSize)
		if _, err := t.CopyInBytes(tailAddr, tail); err != nil {
			return 0, nil, err
		}
		for _, b := range tail {
			if b != 0 {
				return 0, nil, linuxerr.E2BIG
			}
		}
	}
	var handledAccessFS primitive.Uint64
	if _, err := handledAccessFS.CopyIn(t, addr); err != nil {
		return 0, nil, err
	}
	if uint64(handledAccessFS)&^linux.LANDLOCK_ACCESS_FS_V1 != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if handledAccessFS == 0 {
		return 0, nil, linuxerr.ENOMSG
	}

	vfsObj := t.Kernel().VFS()
	ruleset := vfsObj.NewLandlockRuleset(uint64(handledAccessFS))
	file, err := vfsObj.NewLandlockRulesetFD(t, t.Credentials(), ruleset)
	if err != nil {
		ruleset.Release(t)
		return 0, nil, err
	}
	defer file.DecRef(t)
	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

// LandlockAddRule implements Linux syscall landlock_add_rule(2).
func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	if !t.Kernel().LandlockEnabled {
		return 0, nil, linuxerr.ENOSYS
	}
	rulesetFD := args[0].Int()
	ruleType := args[1].Int()
	addr := args[2].Pointer()
	flags := args[3].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)
	ruleset, err := vfs.LandlockRulesetFromFD(rulesetFile, vfs.MayWrite)
	if err != nil {
		return 0, nil, err
	}
	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}
	if addr == 0 {
		return 0, nil, linuxerr.EFAULT
	}
	var attr linux.LandlockPathBeneathAttr
	if _, err := attr.CopyIn(t, addr); err != nil {
		return 0, nil, err
	}
	if attr.AllowedAccess == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if attr.AllowedAccess&^ruleset.HandledAccessFS() != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	parent := t.GetFile(attr.ParentFD)
	if parent == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer parent.DecRef(t)
	// Ruleset files are on an internal mount, so this also refuses a ruleset
	// FD as parent_fd.
	if !parent.Mount().LandlockNameable() {
		return 0, nil, linuxerr.EBADFD
	}
	stat, err := parent.Stat(t, vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err != nil {
		return 0, nil, err
	}
	if stat.Mode&linux.S_IFMT != linux.S_IFDIR && attr.AllowedAccess&^landlockFileAccessFS != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	obj, err := parent.Mount().Filesystem().LandlockObject(parent.Dentry())
	if err != nil {
		return 0, nil, err
	}
	ruleset.AddRule(t, obj, attr.AllowedAccess)
	return 0, nil, nil
}

// LandlockRestrictSelf implements Linux syscall landlock_restrict_self(2).
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	if !t.Kernel().LandlockEnabled {
		return 0, nil, linuxerr.ENOSYS
	}
	rulesetFD := args[0].Int()
	flags := args[1].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if !t.GetNoNewPrivs() && !t.HasSelfCapability(linux.CAP_SYS_ADMIN) {
		return 0, nil, linuxerr.EPERM
	}
	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)
	ruleset, err := vfs.LandlockRulesetFromFD(rulesetFile, vfs.MayRead)
	if err != nil {
		return 0, nil, err
	}
	dom, err := vfs.StackLandlockDomain(t.LandlockDomain(), ruleset)
	if err != nil {
		return 0, nil, err
	}
	t.SetLandlockDomain(dom)
	return 0, nil, nil
}
