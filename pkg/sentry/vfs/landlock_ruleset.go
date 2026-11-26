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

package vfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
)

// LandlockRuleset is a mutable set of Landlock rules. landlock_create_ruleset(2)
// creates one, landlock_add_rule(2) adds rules to it, and
// landlock_restrict_self(2) stacks a snapshot of it onto the calling task's
// domain. A ruleset is reachable only through its LandlockRulesetFD, and
// LandlockRulesetFD.Release releases it when the last reference on the file
// description is dropped; callers hold a reference on the file description
// while they use the ruleset.
//
// +stateify savable
type LandlockRuleset struct {
	// vfs is the VirtualFilesystem that counts the ruleset among its live
	// Landlock rulesets and domains (see VirtualFilesystem.landlockLive), until
	// Release. vfs is immutable.
	vfs *VirtualFilesystem

	// handledAccessFS is the set of filesystem rights that the ruleset
	// handles. handledAccessFS is immutable.
	handledAccessFS uint64

	// mu protects rules.
	mu sync.Mutex `state:"nosave"`

	// rules maps each object that the ruleset has a filesystem rule on to the
	// rights that the rule grants. The ruleset holds one reference on each
	// object in rules.
	rules map[*LandlockObject]uint64
}

// NewLandlockRuleset creates a new LandlockRuleset handling the filesystem
// rights in handledAccessFS.
func (vfs *VirtualFilesystem) NewLandlockRuleset(handledAccessFS uint64) *LandlockRuleset {
	vfs.landlockLive.Add(1)
	return &LandlockRuleset{
		vfs:             vfs,
		handledAccessFS: handledAccessFS,
		rules:           make(map[*LandlockObject]uint64),
	}
}

// HandledAccessFS returns the set of filesystem rights handled by r.
func (r *LandlockRuleset) HandledAccessFS() uint64 {
	return r.handledAccessFS
}

// AddRule adds or extends a rule in r granting the filesystem rights in
// allowedAccessFS on obj. AddRule takes ownership of one reference on obj.
func (r *LandlockRuleset) AddRule(ctx context.Context, obj *LandlockObject, allowedAccessFS uint64) {
	r.mu.Lock()
	prev, ok := r.rules[obj]
	r.rules[obj] = prev | allowedAccessFS
	r.mu.Unlock()
	if ok {
		obj.DecRef(ctx)
	}
}

// Release drops the references that r holds on its objects.
//
// Preconditions: Release is called once, after the last use of r.
func (r *LandlockRuleset) Release(ctx context.Context) {
	r.mu.Lock()
	rules := r.rules
	r.rules = nil
	r.mu.Unlock()
	for obj := range rules {
		obj.DecRef(ctx)
	}
	r.vfs.landlockLive.Add(-1)
}

// LandlockRulesetFD implements FileDescriptionImpl for an anonymous
// "[landlock-ruleset]" file description.
//
// +stateify savable
type LandlockRulesetFD struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	NoLockFD

	ruleset *LandlockRuleset
}

// NewLandlockRulesetFD wraps ruleset in an anonymous "[landlock-ruleset]"
// FileDescription opened read-write. On error, ruleset is not released.
func (vfs *VirtualFilesystem) NewLandlockRulesetFD(ctx context.Context, creds *auth.Credentials, ruleset *LandlockRuleset) (*FileDescription, error) {
	vd := vfs.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(ctx)

	fd := &LandlockRulesetFD{
		ruleset: ruleset,
	}
	if err := fd.vfsfd.Init(fd, linux.O_RDWR, creds, vd.Mount(), vd.Dentry(), &FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
		DenySpliceIn:      true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Release implements FileDescriptionImpl.Release.
func (fd *LandlockRulesetFD) Release(ctx context.Context) {
	fd.ruleset.Release(ctx)
}

// Ruleset returns the underlying LandlockRuleset.
func (fd *LandlockRulesetFD) Ruleset() *LandlockRuleset {
	return fd.ruleset
}

// LandlockRulesetFromFD extracts the LandlockRuleset from fd, checking O_PATH,
// file description type, and required access modes (MayRead / MayWrite).
func LandlockRulesetFromFD(fd *FileDescription, required AccessTypes) (*LandlockRuleset, error) {
	if fd == nil || fd.StatusFlags()&linux.O_PATH != 0 {
		return nil, linuxerr.EBADF
	}
	rfd, ok := fd.Impl().(*LandlockRulesetFD)
	if !ok {
		return nil, linuxerr.EBADFD
	}
	if (required.MayRead() && !fd.IsReadable()) || (required.MayWrite() && !fd.IsWritable()) {
		return nil, linuxerr.EPERM
	}
	return rfd.ruleset, nil
}
