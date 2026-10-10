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

// Package bootapi defines what runsc and the Sentry's boot package share
// without runsc linking the Sentry: controller RPC names and arguments, and
// the OCI spec annotations that both sides interpret.
package bootapi

import (
	"fmt"
	gtime "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	// ContMgrCheckpoint checkpoints a container.
	ContMgrCheckpoint = "containerManager.Checkpoint"

	// ContMgrCreateSubcontainer creates a sub-container.
	ContMgrCreateSubcontainer = "containerManager.CreateSubcontainer"

	// ContMgrDestroySubcontainer is used to stop a sub-container and free all
	// associated resources in the sandbox.
	ContMgrDestroySubcontainer = "containerManager.DestroySubcontainer"

	// ContMgrEvent gets stats about the container used by "runsc events".
	ContMgrEvent = "containerManager.Event"

	// ContMgrExecuteAsync executes a command in a container.
	ContMgrExecuteAsync = "containerManager.ExecuteAsync"

	// ContMgrFSSave saves a filesystem checkpoint.
	ContMgrFSSave = "containerManager.FSSave"

	// ContMgrGetSavings gets the savings for restored sandboxes.
	ContMgrGetSavings = "containerManager.GetSavings"

	// ContMgrPortForward starts port forwarding with the sandbox.
	ContMgrPortForward = "containerManager.PortForward"

	// ContMgrProcesses lists processes running in a container.
	ContMgrProcesses = "containerManager.Processes"

	// ContMgrRestore restores a container from a statefile.
	ContMgrRestore = "containerManager.Restore"

	// ContMgrRestoreSubcontainer restores a container from a statefile.
	ContMgrRestoreSubcontainer = "containerManager.RestoreSubcontainer"

	// ContMgrPause pauses all tasks, blocking until they are stopped.
	ContMgrPause = "containerManager.Pause"

	// ContMgrResume resumes all tasks.
	ContMgrResume = "containerManager.Resume"

	// ContMgrSignal sends a signal to a container.
	ContMgrSignal = "containerManager.Signal"

	// ContMgrStartSubcontainer starts a sub-container inside a running sandbox.
	ContMgrStartSubcontainer = "containerManager.StartSubcontainer"

	// ContMgrWait waits on the init process of the container and returns its
	// ExitStatus.
	ContMgrWait = "containerManager.Wait"

	// ContMgrWaitPID waits on a process with a certain PID in the sandbox and
	// return its ExitStatus.
	ContMgrWaitPID = "containerManager.WaitPID"

	// ContMgrWaitCheckpoint waits for the next Kernel checkpoint to complete.
	ContMgrWaitCheckpoint = "containerManager.WaitCheckpoint"

	// ContMgrWaitRestore waits for the Kernel restore to complete.
	ContMgrWaitRestore = "containerManager.WaitRestore"

	// ContMgrWaitFSCheckpoint waits for the next filesystem checkpoint save to
	// complete.
	ContMgrWaitFSCheckpoint = "containerManager.WaitFSCheckpoint"

	// ContMgrWaitFSRestore waits for filesystem checkpoint restore to complete
	// for all current containers.
	ContMgrWaitFSRestore = "containerManager.WaitFSRestore"

	// ContMgrRootContainerStart starts a new sandbox with a root container.
	ContMgrRootContainerStart = "containerManager.StartRoot"

	// ContMgrCreateTraceSession starts a trace session.
	ContMgrCreateTraceSession = "containerManager.CreateTraceSession"

	// ContMgrDeleteTraceSession deletes a trace session.
	ContMgrDeleteTraceSession = "containerManager.DeleteTraceSession"

	// ContMgrListTraceSessions lists a trace session.
	ContMgrListTraceSessions = "containerManager.ListTraceSessions"

	// ContMgrProcfsDump dumps sandbox procfs state.
	ContMgrProcfsDump = "containerManager.ProcfsDump"

	// ContMgrMount mounts a filesystem in a container.
	ContMgrMount = "containerManager.Mount"

	// ContMgrContainerRuntimeState returns the runtime state of a container.
	ContMgrContainerRuntimeState = "containerManager.ContainerRuntimeState"

	// ContMgrSetNetworkArgs sets network args in loader without creating links.
	ContMgrSetNetworkArgs = "containerManager.SetNetworkArgs"

	// ContMgrGetNetworkConfig returns the network interfaces and routes applied
	// during the creation of root container.
	ContMgrGetNetworkConfig = "containerManager.GetNetworkConfig"
)

const (
	// NetworkCreateLinksAndRoutes synchronously creates links and routes.
	NetworkCreateLinksAndRoutes = "Network.CreateLinksAndRoutes"

	// NetworkInitPluginStack initializes third-party network stack.
	NetworkInitPluginStack = "Network.InitPluginStack"

	// DebugStacks collects sandbox stacks for debugging.
	DebugStacks = "debug.Stacks"
)

// Profiling related commands (see pprof.go for more details).
const (
	ProfileCPU       = "Profile.CPU"
	ProfileHeap      = "Profile.Heap"
	ProfileGoroutine = "Profile.Goroutine"
	ProfileBlock     = "Profile.Block"
	ProfileMutex     = "Profile.Mutex"
	ProfileTrace     = "Profile.Trace"
)

// Logging related commands (see logging.go for more details).
const (
	LoggingChange = "Logging.Change"
)

// Usage related commands (see usage.go for more details).
const (
	UsageCollect = "Usage.Collect"
	UsageUsageFD = "Usage.UsageFD"
)

// Metrics related commands (see metrics.go).
const (
	MetricsGetRegistered = "Metrics.GetRegisteredMetrics"
	MetricsExport        = "Metrics.Export"
)

// Commands for interacting with cgroupfs within the sandbox.
const (
	CgroupsReadControlFiles  = "Cgroups.ReadControlFiles"
	CgroupsWriteControlFiles = "Cgroups.WriteControlFiles"
)

// FS-related commands (see fs.go for more details).
const (
	FsTarRootfsUpperLayer = "Fs.TarRootfsUpperLayer"
	FsRead                = "Fs.Read"
)

// CreateArgs contains arguments to the Create method.
type CreateArgs struct {
	// CID is the ID of the container to start.
	CID string

	// FilePayload may contain a TTY file for the terminal, if enabled.
	urpc.FilePayload
}

// StartArgs contains arguments to the Start method.
type StartArgs struct {
	// Spec is the spec of the container to start.
	Spec *specs.Spec

	// Config is the runsc-specific configuration for the sandbox.
	Conf *config.Config

	// CID is the ID of the container to start.
	CID string

	// NumGoferFilestoreFDs is the number of gofer filestore FDs donated.
	NumGoferFilestoreFDs int

	// IsDevIoFilePresent indicates whether the dev gofer FD is present.
	IsDevIoFilePresent bool

	// GoferMountConfs contains information about how the gofer mounts have been
	// configured. The first entry is for rootfs and the following entries are
	// for bind mounts in Spec.Mounts (in the same order).
	GoferMountConfs []specutils.GoferMountConf

	// IsRootfsUpperTarFilePresent indicates whether the rootfs upper tar file is present.
	IsRootfsUpperTarFilePresent bool

	// FilePayload contains, in order:
	//   * stdin, stdout, and stderr (optional: if terminal is disabled).
	//   * file descriptors to gofer-backing host files (optional).
	//   * file descriptor for /dev gofer connection (optional)
	//   * file descriptor for rootfs upper tar file (optional)
	//   * file descriptors to connect to gofer to serve the root filesystem.
	urpc.FilePayload
}

// PortForwardOpts contains options for port forwarding to a port in a
// container.
type PortForwardOpts struct {
	// FilePayload contains one fd for a UDS (or local port) used for port
	// forwarding.
	urpc.FilePayload

	// ContainerID is the container for the process being executed.
	ContainerID string
	// Port is the port to to forward.
	Port uint16
}

// RestoreOpts contains options related to restoring a container's file system.
type RestoreOpts struct {
	// FilePayload contains, in order:
	// 1. checkpoint state file.
	// 2. optional checkpoint pages metadata file.
	// 3. optional checkpoint pages file.
	// 4. optional platform device file.
	urpc.FilePayload
	HavePagesFile  bool
	HaveDeviceFile bool
	Background     bool

	// If UseCheckpointGofer is true, the first file in FilePayload is a Unix
	// domain socket connected to a URPC server implementing
	// stateipc.AsyncFileServer and providing checkpoint files. In this case,
	// RestoreOpts.HavePagesFile is unknown and must be determined by
	// containerManager.Restore.
	UseCheckpointGofer bool `json:"use_checkpoint_gofer"`

	// SplitFSRestore indicates if we should restore the filesystem from a
	// split filesystem checkpoint.
	SplitFSRestore bool `json:"split_fsrestore"`
}

// WaitPIDArgs are arguments to the WaitPID method.
type WaitPIDArgs struct {
	// PID is the PID in the container's PID namespace.
	PID int32

	// CID is the container ID.
	CID string
}

// WaitFSRestoreArgs holds arguments to containerManager.WaitFSRestore.
type WaitFSRestoreArgs struct {
	// CID is the container ID.
	CID string
}

// SignalDeliveryMode enumerates different signal delivery modes.
type SignalDeliveryMode int

const (
	// DeliverToProcess delivers the signal to the container process with
	// the specified PID. If PID is 0, then the container init process is
	// signaled.
	DeliverToProcess SignalDeliveryMode = iota

	// DeliverToAllProcesses delivers the signal to all processes in the
	// container. PID must be 0.
	DeliverToAllProcesses

	// DeliverToForegroundProcessGroup delivers the signal to the
	// foreground process group in the same TTY session as the specified
	// process. If PID is 0, then the signal is delivered to the foreground
	// process group for the TTY for the init process.
	DeliverToForegroundProcessGroup

	// DeliverToProcessGroup delivers the signal to all processes in the
	// process group identified by a PGID.
	DeliverToProcessGroup
)

func (s SignalDeliveryMode) String() string {
	switch s {
	case DeliverToProcess:
		return "Process"
	case DeliverToAllProcesses:
		return "All"
	case DeliverToForegroundProcessGroup:
		return "Foreground Process Group"
	case DeliverToProcessGroup:
		return "Process Group"
	}
	return fmt.Sprintf("unknown signal delivery mode: %d", s)
}

// SignalArgs are arguments to the Signal method.
type SignalArgs struct {
	// CID is the container ID.
	CID string

	// Signo is the signal to send to the process.
	Signo int32

	// PID is the process ID in the given container that will be signaled,
	// relative to the root PID namespace, not the container's.
	// If 0, the root container will be signalled.
	PID int32

	// Mode is the signal delivery mode.
	Mode SignalDeliveryMode
}

// CreateTraceSessionArgs are arguments to the CreateTraceSession method.
type CreateTraceSessionArgs struct {
	Config seccheck.SessionConfig
	Force  bool
	urpc.FilePayload
}

// MountArgs contains arguments to the Mount method.
type MountArgs struct {
	// ContainerID is the container in which we will mount the filesystem.
	ContainerID string

	// Source is the mount source.
	Source string

	// Destination is the mount target.
	Destination string

	// FsType is the filesystem type.
	FsType string

	// FilePayload contains the source image FD, if required by the filesystem.
	urpc.FilePayload
}

// FSSaveArgs holds arguments to FSSave.
type FSSaveArgs struct {
	// FilePayload contains the following fscheckpoint files in order:
	// 1. manifest file
	// 2. multi-tar file
	// 3. pages metadata file
	// 4. pages file
	urpc.FilePayload

	// Paths are the paths inside the containers to save to the checkpoint.
	Paths []checkpoint.ResourceID `json:"paths"`

	// Equivalent to kernel.FSSaveOpts fields.
	ExitAfterSaving bool `json:"exit_after_saving"`

	// If UseCheckpointGofer is true, FSSaveArgs.FilePayload should contain
	// exactly one FD, which is a Unix domain socket connected to a URPC server
	// implementing stateipc.AsyncFileServer.
	UseCheckpointGofer bool `json:"use_checkpoint_gofer"`
}

// Savings holds the savings with restore.
type Savings struct {
	// CPUTimeSaved is the CPU time saved at restore.
	CPUTimeSaved gtime.Duration
	// WallTimeSaved is the wall time saved at restore.
	WallTimeSaved gtime.Duration
}
