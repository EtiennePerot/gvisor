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

package boot

import "gvisor.dev/gvisor/runsc/boot/bootapi"

// Aliases of bootapi declarations that the Sentry side also uses.

// CPU contains stats on the CPU.
type CPU = bootapi.CPU

// ContainerRuntimeState is the runtime state of a container.
type ContainerRuntimeState = bootapi.ContainerRuntimeState

// CreateArgs contains arguments to the Create method.
type CreateArgs = bootapi.CreateArgs

// CreateLinksAndRoutesArgs are arguments to CreateLinkAndRoutes.
type CreateLinksAndRoutesArgs = bootapi.CreateLinksAndRoutesArgs

// CreateTraceSessionArgs are arguments to the CreateTraceSession method.
type CreateTraceSessionArgs = bootapi.CreateTraceSessionArgs

// Event struct for encoding the event data to JSON. Corresponds to runc's
// main.event struct.
type Event = bootapi.Event

// EventOut is the return type of the Event command.
type EventOut = bootapi.EventOut

// FDMapping is a helper type to represent a mapping from guest to host file
// descriptors. In contrast to the unexported fdMapping type, it does not imply
// file ownership.
type FDMapping = bootapi.FDMapping

// FSSaveArgs holds arguments to FSSave.
type FSSaveArgs = bootapi.FSSaveArgs

// IPWithPrefix is an address with its subnet prefix length.
type IPWithPrefix = bootapi.IPWithPrefix

// InitConfig represents the configuration to apply during pod creation. For
// now, it supports setting up a seccheck session.
type InitConfig = bootapi.InitConfig

// InitPluginStackArgs are arguments to InitPluginStack.
type InitPluginStackArgs = bootapi.InitPluginStackArgs

// LoopbackLink configures a loopback link.
type LoopbackLink = bootapi.LoopbackLink

// MountArgs contains arguments to the Mount method.
type MountArgs = bootapi.MountArgs

// MountHint represents extra information about mounts that are provided via
// annotations. They can override mount type, provide sharing information so
// that mounts can be correctly shared inside the pod, and tune gofer-specific
// behavior such as suppressing directfs.
// It is part of the sandbox.Sandbox struct, so it must be serializable.
type MountHint = bootapi.MountHint

// NetworkInterface is the network statistics of the particular network interface
type NetworkInterface = bootapi.NetworkInterface

// PodMountHints contains a collection of mountHints for the pod.
type PodMountHints = bootapi.PodMountHints

// PortForwardOpts contains options for port forwarding to a port in a
// container.
type PortForwardOpts = bootapi.PortForwardOpts

// RestoreOpts contains options related to restoring a container's file system.
type RestoreOpts = bootapi.RestoreOpts

// Route represents a route in the network stack.
type Route = bootapi.Route

// Savings holds the savings with restore.
type Savings = bootapi.Savings

// SignalArgs are arguments to the Signal method.
type SignalArgs = bootapi.SignalArgs

// SignalDeliveryMode enumerates different signal delivery modes.
type SignalDeliveryMode = bootapi.SignalDeliveryMode

// StartArgs contains arguments to the Start method.
type StartArgs = bootapi.StartArgs

// Stats is the runc specific stats structure for stability when encoding and
// decoding stats.
type Stats = bootapi.Stats

// WaitFSRestoreArgs holds arguments to containerManager.WaitFSRestore.
type WaitFSRestoreArgs = bootapi.WaitFSRestoreArgs

// WaitPIDArgs are arguments to the WaitPID method.
type WaitPIDArgs = bootapi.WaitPIDArgs

const (
	Bind                            = bootapi.Bind
	BindRunsc                       = bootapi.BindRunsc
	BindSentry                      = bootapi.BindSentry
	DeliverToAllProcesses           = bootapi.DeliverToAllProcesses
	DeliverToForegroundProcessGroup = bootapi.DeliverToForegroundProcessGroup
	DeliverToProcess                = bootapi.DeliverToProcess
	DeliverToProcessGroup           = bootapi.DeliverToProcessGroup
	MountPrefix                     = bootapi.MountPrefix
	Nonefs                          = bootapi.Nonefs
	RuntimeStateCreating            = bootapi.RuntimeStateCreating
	RuntimeStateRunning             = bootapi.RuntimeStateRunning
	RuntimeStateStopped             = bootapi.RuntimeStateStopped
	annotationFSCheckpointEnable    = bootapi.AnnotationFSCheckpointEnable
	annotationFSCheckpointPaths     = bootapi.AnnotationFSCheckpointPaths
	annotationFSCheckpointResume    = bootapi.AnnotationFSCheckpointResume
)

// DefaultLoopbackLink contains IP addresses and routes of "127.0.0.1/8" and
// "::1/8" on "lo" interface.
var DefaultLoopbackLink = bootapi.DefaultLoopbackLink
