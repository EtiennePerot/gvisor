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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// landlockAttachment ties a live LandlockObject to its file.
type landlockAttachment struct {
	// fs is the filesystem of the file. fs is immutable.
	fs *Filesystem

	// dentry is a dentry of the file. The object holds a reference on dentry,
	// which keeps the file's state alive while rules name it. dentry is
	// immutable.
	dentry *Dentry

	// slots are the LandlockSlots that hold the object. slots is protected
	// by fs.landlockMu.
	slots []LandlockSlot
}

// LandlockObject is the identity of a file to Landlock rules. Rules and
// checks refer to files only through their objects.
//
// An object belongs to the file, not to a path: every name of the file,
// including hard links and bind mounts, finds the same object through the
// LandlockSlot of its dentries. For example, if a rule is added through
// /a/dir and then /a/dir is renamed to /b/dir, the rule still names the
// directory, so it still applies to /b/dir and to the files beneath it. A rule
// on /a no longer covers the directory, because the ancestor walk from the
// directory no longer passes /a.
//
// A file gets an object when the first rule naming it is created. The object
// is reachable from the file only while a slot holds it. Slots stop holding
// it when its last reference is dropped, or when its filesystem is destroyed;
// a later rule for the file gets a new object.
//
// +stateify savable
type LandlockObject struct {
	// refs is the number of references on the object. Each ruleset and each
	// domain with a rule on the object holds one reference, as does a caller
	// of Filesystem.LandlockObject until it hands the reference to a ruleset.
	// Once refs reaches zero, it never increases again.
	refs atomicbitops.Int64

	// att ties the object to its file. att is nil once the object has been
	// released or its filesystem has been destroyed. att is set when the
	// object is created, and cleared with its filesystem's landlockMu locked.
	att atomic.Pointer[landlockAttachment] `state:"nosave"`
}

// IncRef increments o's reference count. The caller must already hold a
// reference on o.
func (o *LandlockObject) IncRef() {
	if o.refs.Add(1) <= 1 {
		panic("vfs.LandlockObject.IncRef called without holding a reference")
	}
}

// DecRef decrements o's reference count. If this drops the last reference, o
// is removed from the slots that hold it and drops its dentry reference.
//
// Preconditions: The caller must not hold locks of the filesystem that o's
// file belongs to.
func (o *LandlockObject) DecRef(ctx context.Context) {
	r := o.refs.Add(-1)
	if r < 0 {
		panic("vfs.LandlockObject.DecRef called without holding a reference")
	}
	if r == 0 {
		o.release(ctx)
	}
}

// tryIncRef increments o's reference count and returns true if o still has a
// reference. An object whose last reference has been dropped is never
// revived, even though a slot may hold it until its release removes it.
func (o *LandlockObject) tryIncRef() bool {
	for {
		r := o.refs.Load()
		if r <= 0 {
			return false
		}
		if o.refs.CompareAndSwap(r, r+1) {
			return true
		}
	}
}

// release removes o from the slots that hold it and drops o's dentry
// reference after the last reference on o has been dropped.
func (o *LandlockObject) release(ctx context.Context) {
	att := o.att.Load()
	if att == nil {
		return
	}
	fs := att.fs
	fs.landlockMu.Lock()
	// Hold a reference on fs while dropping the dentry reference, so that fs
	// cannot be destroyed under the dentry. If fs is already being destroyed,
	// detachLandlockObjects drops the dentry reference instead.
	if !fs.TryIncRef() {
		fs.landlockMu.Unlock()
		return
	}
	att = o.att.Swap(nil)
	if att != nil {
		delete(fs.landlockObjects, o)
		att.removeFromSlotsLocked(o)
	}
	fs.landlockMu.Unlock()
	if att != nil {
		att.dentry.DecRef(ctx)
	}
	fs.DecRef(ctx)
}

// removeFromSlotsLocked removes o from each slot in att.slots that still holds
// o. A slot that holds a new object for the same file, installed after o's
// last reference was dropped, keeps the new object.
//
// Preconditions: att.fs.landlockMu must be locked.
func (att *landlockAttachment) removeFromSlotsLocked(o *LandlockObject) {
	for _, slot := range att.slots {
		slot.removeLocked(o)
	}
	att.slots = nil
}

// newLandlockObjectLocked creates and registers a new LandlockObject on fs for
// d with initial reference count 1 and installs it in slot.
//
// Preconditions: fs.landlockMu must be locked and !fs.landlockDetached.
func (fs *Filesystem) newLandlockObjectLocked(d *Dentry, slot LandlockSlot) *LandlockObject {
	d.IncRef()
	obj := &LandlockObject{
		refs: atomicbitops.FromInt64(1),
	}
	obj.att.Store(&landlockAttachment{
		fs:     fs,
		dentry: d,
	})
	if fs.landlockObjects == nil {
		fs.landlockObjects = make(map[*LandlockObject]struct{})
	}
	fs.landlockObjects[obj] = struct{}{}
	fs.installLandlockObjectLocked(obj, slot)
	return obj
}

// installLandlockObjectLocked installs obj in slot, in addition to the slots
// that already hold obj. When obj is released, it is removed from every slot
// that holds it.
//
// Preconditions: fs.landlockMu must be locked. obj is a live LandlockObject
// of a file on fs.
func (fs *Filesystem) installLandlockObjectLocked(obj *LandlockObject, slot LandlockSlot) {
	att := obj.att.Load()
	att.slots = append(att.slots, slot)
	slot.storeLocked(obj)
}

// ShareLandlockObject makes to hold the live LandlockObject that from holds,
// if any, in addition to the slots that already hold it; then it calls
// publish, which typically makes the file's dentries use to instead of from.
// Both steps happen with landlockMu locked, so Filesystem.LandlockObject for
// the file runs entirely before or entirely after them, and the file keeps its
// object when it moves to a new slot. from keeps holding the object, so other
// names of the file that still use from keep finding it. publish must not
// acquire locks.
//
// Preconditions: from and to locate objects of files on fs, if not nil.
func (fs *Filesystem) ShareLandlockObject(from, to LandlockSlot, publish func()) {
	fs.landlockMu.Lock()
	defer fs.landlockMu.Unlock()
	if from != nil && to != nil {
		// from holds an object only while the object is attached, since
		// release and detach remove it from every slot under landlockMu.
		if obj := from.lookup(); obj != nil {
			fs.installLandlockObjectLocked(obj, to)
		}
	}
	publish()
}

// detachLandlockObjects detaches every LandlockObject belonging to fs and
// drops its dentry reference before fs.impl.Release runs.
func (fs *Filesystem) detachLandlockObjects(ctx context.Context) {
	fs.landlockMu.Lock()
	fs.landlockDetached = true
	var dentries []*Dentry
	for obj := range fs.landlockObjects {
		if att := obj.att.Swap(nil); att != nil {
			att.removeFromSlotsLocked(obj)
			dentries = append(dentries, att.dentry)
		}
	}
	fs.landlockObjects = nil
	fs.landlockMu.Unlock()

	for _, d := range dentries {
		d.DecRef(ctx)
	}
}

// LandlockObject returns the LandlockObject of the file that d represents,
// with a reference taken for the caller. It creates the object if the file
// has none. It returns EBADFD if Landlock rules cannot name the file.
//
// Preconditions: d is a dentry of fs. The caller holds a reference on d.
func (fs *Filesystem) LandlockObject(d *Dentry) (*LandlockObject, error) {
	fs.landlockMu.Lock()
	defer fs.landlockMu.Unlock()
	// Get the slot with landlockMu locked, so that a concurrent
	// ShareLandlockObject for the file runs entirely before or after this.
	slot := d.impl.LandlockSlot()
	if slot == nil || fs.landlockDetached {
		return nil, linuxerr.EBADFD
	}
	// An object whose last reference has been dropped is replaced, never
	// revived.
	if cur := slot.lookup(); cur != nil && cur.tryIncRef() {
		return cur, nil
	}
	return fs.newLandlockObjectLocked(d, slot), nil
}

// LookupLandlockObject returns the live LandlockObject of the file that d
// represents, or nil if it has none. It takes no locks.
func (d *Dentry) LookupLandlockObject() *LandlockObject {
	if slot := d.impl.LandlockSlot(); slot != nil {
		return slot.lookup()
	}
	return nil
}

// LandlockSlot locates the LandlockObject of a file. Filesystems store a
// LandlockFileSlot or a LandlockKeySlot for each file that Landlock rules can
// name, and return it from DentryImpl.LandlockSlot.
type LandlockSlot interface {
	// lookup returns the live LandlockObject in the slot, or nil. It takes
	// no locks.
	lookup() *LandlockObject

	// storeLocked installs obj in the slot, replacing any previous object.
	//
	// Preconditions: The filesystem's landlockMu must be locked.
	storeLocked(obj *LandlockObject)

	// removeLocked removes obj from the slot if the slot holds obj.
	//
	// Preconditions: The filesystem's landlockMu must be locked.
	removeLocked(obj *LandlockObject)
}

// LandlockFileSlot is a LandlockSlot that holds the LandlockObject of one
// file. Filesystems embed it in the state they keep for the file.
//
// +stateify savable
type LandlockFileSlot struct {
	ptr atomic.Pointer[LandlockObject] `state:"nosave"`
}

// lookup implements LandlockSlot.lookup.
func (s *LandlockFileSlot) lookup() *LandlockObject {
	return s.ptr.Load()
}

// storeLocked implements LandlockSlot.storeLocked.
func (s *LandlockFileSlot) storeLocked(obj *LandlockObject) {
	s.ptr.Store(obj)
}

// removeLocked implements LandlockSlot.removeLocked.
func (s *LandlockFileSlot) removeLocked(obj *LandlockObject) {
	s.ptr.CompareAndSwap(obj, nil)
}

// LandlockKeyMap maps keys to the LandlockObjects of files on a filesystem.
// Filesystems use it when a file's identity is not tied to the state they
// keep for the file. For example, FUSE keys a file by the server's node ID and
// generation, so that its identity outlives the inode; overlay keys a file by
// the layer file that its identity follows. A key may be of any comparable
// type, and keys of different types never match. Lookups take no locks.
// Storing and removing an object costs time independent of the number of
// objects in the map.
//
// +stateify savable
type LandlockKeyMap struct {
	objs landlockKeyAtomicPtrMap `state:"nosave"`
}

// Slot returns a LandlockKeySlot that locates the LandlockObject for key in
// m. key must be comparable.
func (m *LandlockKeyMap) Slot(key any) LandlockKeySlot {
	return LandlockKeySlot{m: m, key: key}
}

// LandlockKeySlot is a LandlockSlot that locates the LandlockObject of a file
// in a LandlockKeyMap under one key. LandlockKeySlot is immutable.
//
// +stateify savable
type LandlockKeySlot struct {
	m   *LandlockKeyMap
	key any
}

// lookup implements LandlockSlot.lookup.
func (s *LandlockKeySlot) lookup() *LandlockObject {
	return s.m.objs.Load(s.key)
}

// storeLocked implements LandlockSlot.storeLocked.
func (s *LandlockKeySlot) storeLocked(obj *LandlockObject) {
	s.m.objs.Store(s.key, obj)
}

// removeLocked implements LandlockSlot.removeLocked.
func (s *LandlockKeySlot) removeLocked(obj *LandlockObject) {
	s.m.objs.CompareAndSwap(s.key, obj, nil)
}
