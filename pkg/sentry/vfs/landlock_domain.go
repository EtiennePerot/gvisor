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
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// landlockLayerAccess is the filesystem access that one layer of a
// LandlockDomain grants on a LandlockObject.
//
// +stateify savable
type landlockLayerAccess struct {
	// layer is the index of the layer in the domain.
	layer uint8

	// accessFS is the set of filesystem rights that the layer grants.
	accessFS uint64
}

// LandlockDomain is an immutable stack of 1 to 16 Landlock layers enforced on
// a task. Each layer is a snapshot of one ruleset. A request is allowed if
// every layer grants each requested right that it handles, through rules on
// the file or on any directory that the ancestor walk visits.
//
// +stateify savable
type LandlockDomain struct {
	// refs is the number of references on the domain. Each task whose
	// credentials carry the domain holds one reference. When refs reaches
	// zero, the domain drops its references on its objects; refs never
	// increases again after that.
	refs atomicbitops.Int64

	// vfs is the VirtualFilesystem that counts the domain among its live
	// Landlock rulesets and domains (see VirtualFilesystem.landlockLive),
	// until refs reaches zero. vfs is immutable.
	vfs *VirtualFilesystem

	// parent is the domain that this domain was stacked onto, or nil. Only
	// parent's identity is used, for ptrace scoping (CanPtrace); parent may
	// have been released, and holds no references on its objects then.
	// parent is immutable.
	parent *LandlockDomain

	// handledAccessFS[i] is the set of filesystem rights that layer i
	// handles. len(handledAccessFS) is the number of layers. handledAccessFS
	// is immutable.
	handledAccessFS []uint64

	// rules maps each object that any layer has a filesystem rule on to the
	// access that those layers grant on it, in increasing layer order. The domain holds
	// one reference on each object in rules. rules and its slices are
	// immutable; stacking copies a slice before it appends to it.
	rules map[*LandlockObject][]landlockLayerAccess
}

var _ auth.LandlockDomain = (*LandlockDomain)(nil)

// LandlockDomainOf returns the Landlock domain carried in creds, or nil if
// creds carries none.
func LandlockDomainOf(creds *auth.Credentials) *LandlockDomain {
	if creds == nil {
		return nil
	}
	dom, _ := creds.LandlockDomain.(*LandlockDomain)
	return dom
}

// StackLandlockDomain creates a new LandlockDomain by stacking a snapshot of
// ruleset onto parent (which may be nil). Returns E2BIG if parent already has
// 16 layers.
func StackLandlockDomain(parent *LandlockDomain, ruleset *LandlockRuleset) (*LandlockDomain, error) {
	var parentHandled []uint64
	var parentRules map[*LandlockObject][]landlockLayerAccess
	if parent != nil {
		if len(parent.handledAccessFS) >= linux.LANDLOCK_MAX_NUM_LAYERS {
			return nil, linuxerr.E2BIG
		}
		parentHandled = parent.handledAccessFS
		parentRules = parent.rules
	}

	ruleset.mu.Lock()
	defer ruleset.mu.Unlock()

	layer := uint8(len(parentHandled))
	handled := append(parentHandled[:len(parentHandled):len(parentHandled)], ruleset.handledAccessFS)

	rules := make(map[*LandlockObject][]landlockLayerAccess, len(parentRules)+len(ruleset.rules))
	for obj, grants := range parentRules {
		obj.IncRef()
		rules[obj] = grants
	}
	for obj, access := range ruleset.rules {
		grants, ok := rules[obj]
		if !ok {
			obj.IncRef()
		}
		// The three-index slice makes append copy grants, so the parent's
		// slice is never modified.
		rules[obj] = append(grants[:len(grants):len(grants)], landlockLayerAccess{
			layer:    layer,
			accessFS: access,
		})
	}

	ruleset.vfs.landlockLive.Add(1)
	return &LandlockDomain{
		refs:            atomicbitops.FromInt64(1),
		vfs:             ruleset.vfs,
		parent:          parent,
		handledAccessFS: handled,
		rules:           rules,
	}, nil
}

// NumLayers returns the number of stacked layers in d (1..16).
func (d *LandlockDomain) NumLayers() int {
	return len(d.handledAccessFS)
}

// HandledAccessFS returns the union of filesystem rights handled by any layer
// in d.
func (d *LandlockDomain) HandledAccessFS() uint64 {
	var access uint64
	for _, h := range d.handledAccessFS {
		access |= h
	}
	return access
}

// IncRef increments d's reference count. The caller must already hold a
// reference on d. IncRef does nothing if d is nil.
func (d *LandlockDomain) IncRef() {
	if d == nil {
		return
	}
	if d.refs.Add(1) <= 1 {
		panic("vfs.LandlockDomain.IncRef called without holding a reference")
	}
}

// DecRef decrements d's reference count. When it drops the last reference, d
// drops its references on its objects. DecRef does nothing if d is nil.
func (d *LandlockDomain) DecRef(ctx context.Context) {
	if d == nil {
		return
	}
	r := d.refs.Add(-1)
	if r < 0 {
		panic("vfs.LandlockDomain.DecRef called without holding a reference")
	}
	if r != 0 {
		return
	}
	for obj := range d.rules {
		obj.DecRef(ctx)
	}
	d.vfs.landlockLive.Add(-1)
}

// CheckMountChange returns EPERM if d does not allow its task to change the
// mount tree, as by mount(2), umount2(2), pivot_root(2), move_mount(2) or a
// remount through fsconfig(2), and nil otherwise. Any domain refuses mount
// changes, whatever rights it handles, so that a task cannot escape its rules
// by remounting; a nil d allows them.
func (d *LandlockDomain) CheckMountChange() error {
	if d != nil {
		return linuxerr.EPERM
	}
	return nil
}

// CanPtrace implements auth.LandlockDomain.CanPtrace.
func (d *LandlockDomain) CanPtrace(tracee auth.LandlockDomain) bool {
	if d == nil {
		return true
	}
	o, _ := tracee.(*LandlockDomain)
	for cur := o; cur != nil; cur = cur.parent {
		if cur == d {
			return true
		}
	}
	return false
}

// landlockCheckState tracks, during an ancestor walk, the requested
// filesystem rights that each layer of a domain has not granted yet.
type landlockCheckState struct {
	dom *LandlockDomain

	// unmet[i] is the set of requested rights that layer i handles and has
	// not granted yet.
	unmet [linux.LANDLOCK_MAX_NUM_LAYERS]uint64

	// pending has bit i set if unmet[i] != 0.
	pending uint32
}

// init initializes s for evaluating the filesystem rights in reqAccessFS under
// dom. Returns true if the check is already satisfied without needing to walk
// any objects.
func (s *landlockCheckState) init(dom *LandlockDomain, reqAccessFS uint64) bool {
	s.dom = dom
	for i, h := range dom.handledAccessFS {
		if u := reqAccessFS & h; u != 0 {
			s.unmet[i] = u
			s.pending |= 1 << i
		}
	}
	return s.pending == 0
}

// visitObject applies the grants on obj from s.dom. Returns false once every
// layer has granted every requested right that it handles (signaling the walk
// to stop early), or true if walking must continue.
func (s *landlockCheckState) visitObject(obj *LandlockObject) bool {
	if obj == nil {
		return true
	}
	for _, g := range s.dom.rules[obj] {
		bit := uint32(1) << g.layer
		if s.pending&bit == 0 {
			continue
		}
		if s.unmet[g.layer] &^= g.accessFS; s.unmet[g.layer] == 0 {
			s.pending &^= bit
		}
	}
	return s.pending != 0
}

// CheckAccessFS returns nil if d allows the filesystem rights in reqAccessFS
// on the file at vd, and EACCES otherwise. Each layer of d must grant every
// requested right that it handles, through rules on the file or on a
// directory that the ancestor walk from vd visits; the walk ends at the root
// of the mount namespace. A nil d allows all access, and files reached through
// internal mounts are always allowed.
//
// The walk takes references on the mounts and mount points that it crosses.
// CheckAccessFS hands them to deferred, and the caller must call
// deferred.Release after it releases its filesystem locks. If deferred is nil,
// CheckAccessFS drops them before it returns; the caller must then hold no
// filesystem locks.
//
// Preconditions: The caller holds a reference on vd, if vd.Ok().
func (d *LandlockDomain) CheckAccessFS(ctx context.Context, vd VirtualDentry, reqAccessFS uint64, deferred *DeferredDecRefs) error {
	if d == nil {
		return nil
	}
	if !vd.Ok() {
		return linuxerr.EACCES
	}
	if vd.mount.IsInternal() {
		return nil
	}
	var state landlockCheckState
	if state.init(d, reqAccessFS) {
		return nil
	}
	if deferred == nil {
		var local DeferredDecRefs
		defer local.Release(ctx)
		deferred = &local
	}
	return walkLandlockMounts(ctx, &state, vd.mount, vd.dentry, deferred)
}

// CheckParentlessFileAccessFS is like CheckAccessFS for a file whose dentry
// has no parent although the file belongs to directory dir, such as a message
// queue opened by name through mq_open(2), whose dentry is not linked into
// its mqueue filesystem's tree. Rules on the file itself apply, and then the
// ancestor walk runs from dir.
//
// Preconditions: file is a dentry of dir.Mount()'s filesystem. The caller
// holds references on file and on dir, if dir.Ok().
func (d *LandlockDomain) CheckParentlessFileAccessFS(ctx context.Context, file *Dentry, dir VirtualDentry, reqAccessFS uint64, deferred *DeferredDecRefs) error {
	if d == nil {
		return nil
	}
	if file == nil || !dir.Ok() {
		return linuxerr.EACCES
	}
	if dir.mount.IsInternal() {
		return nil
	}
	var state landlockCheckState
	if state.init(d, reqAccessFS) {
		return nil
	}
	if !state.visitObject(file.LookupLandlockObject()) {
		return nil
	}
	if deferred == nil {
		var local DeferredDecRefs
		defer local.Release(ctx)
		deferred = &local
	}
	return walkLandlockMounts(ctx, &state, dir.mount, dir.dentry, deferred)
}

// CheckLandlock checks the filesystem rights in reqAccessFS on file d, reached
// through rp.Mount(), against the Landlock domain of rp's credentials, as
// LandlockDomain.CheckAccessFS does. rp owns the references that the ancestor
// walk takes, and drops them in rp.Release, so FilesystemImpl methods may call
// CheckLandlock with filesystem locks held.
//
// Preconditions: d is a dentry of rp.Mount()'s filesystem. The caller holds a
// reference on d.
func (rp *ResolvingPath) CheckLandlock(ctx context.Context, d *Dentry, reqAccessFS uint64) error {
	return LandlockDomainOf(rp.creds).CheckAccessFS(ctx, VirtualDentry{mount: rp.mount, dentry: d}, reqAccessFS, &rp.deferred)
}

// walkLandlockMounts runs the ancestor walk from d reached through mnt and
// applies the LandlockObject of each visited file to state. It returns nil
// once state is satisfied, or EACCES if the walk ends first. References that
// the walk takes on mounts and mount points go to deferred.
//
// The walk visits d and its ancestors up to mnt's root. At mnt's root, it
// continues at mnt's mount point in the parent mount, but skips the covered
// directory itself. It ends at the root of the mount namespace, or after the
// root of a mount that has no parent.
//
// Preconditions: deferred != nil. The caller holds references on mnt and d.
func walkLandlockMounts(ctx context.Context, state *landlockCheckState, mnt *Mount, d *Dentry, deferred *DeferredDecRefs) error {
	skipStart := false
	for {
		root := mnt.root
		satisfied := false
		reachedRoot := false
		mnt.fs.impl.WalkAncestors(d, func(cur *Dentry) bool {
			if skipStart {
				// cur is the directory covered by the previous mount.
				skipStart = false
				return true
			}
			if !state.visitObject(cur.LookupLandlockObject()) {
				satisfied = true
				return false
			}
			if cur == root {
				reachedRoot = true
				return false
			}
			return true
		})
		if satisfied {
			return nil
		}
		if !reachedRoot && root != nil {
			// The walk reached the top of the filesystem without passing
			// mnt's root, so d is outside the subtree that mnt exposes: d was
			// moved out of a bind mount's subtree after it was reached through
			// the bind mount. d is still reached through mnt, so visit mnt's
			// root as if d were beneath it, then continue at mnt's mount point.
			if !state.visitObject(root.LookupLandlockObject()) {
				return nil
			}
		}

		// getMountpointAt skips mounts stacked directly on the root of their
		// parent mount. An empty vfsroot makes it climb past the task's root
		// directory.
		next := mnt.vfs.getMountpointAt(ctx, mnt, VirtualDentry{}, deferred)
		if !next.Ok() {
			return linuxerr.EACCES
		}
		deferred.add(next.mount)
		deferred.add(next.dentry)
		if next.dentry == next.mount.root {
			// The covered directory is the root of a mount that has no
			// parent, so it has no parent to visit.
			return linuxerr.EACCES
		}
		mnt = next.mount
		d = next.dentry
		skipStart = true
	}
}
