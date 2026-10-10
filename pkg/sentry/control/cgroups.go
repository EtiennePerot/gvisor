// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package control

import (
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Cgroups contains the state for cgroupfs related control commands.
type Cgroups struct {
	Kernel *kernel.Kernel
}

func (c *Cgroups) findCgroup(ctx context.Context, file CgroupControlFile) (kernel.Cgroup, error) {
	ctl, err := kernel.ParseCgroupController(file.Controller)
	if err != nil {
		return kernel.Cgroup{}, err
	}
	return c.Kernel.CgroupRegistry().FindCgroup(ctx, ctl, file.Path)
}

// CgroupControlFile identifies a specific control file within a
// specific cgroup, for the hierarchy with a given controller.
type CgroupControlFile = controlapi.CgroupControlFile

// CgroupsResult represents the result of a cgroup operation.
type CgroupsResult = controlapi.CgroupsResult

func newValue(val string) CgroupsResult {
	return CgroupsResult{
		Data: strings.TrimSpace(val),
	}
}

func newError(err error) CgroupsResult {
	return CgroupsResult{
		Data:    err.Error(),
		IsError: true,
	}
}

// CgroupsResults represents the list of results for a batch command.
type CgroupsResults = controlapi.CgroupsResults

// CgroupsReadArg represents the arguments for a single read command.
type CgroupsReadArg = controlapi.CgroupsReadArg

// CgroupsReadArgs represents the list of arguments for a batched read command.
type CgroupsReadArgs = controlapi.CgroupsReadArgs

// cgroup is an interface implemented by both kernel.Cgroup and kernel.Cgroup2.
type cgroup interface {
	ReadControl(ctx context.Context, name string) (string, error)
	WriteControl(ctx context.Context, name string, val string) error
}

func (c *Cgroups) resolveCgroup(ctx context.Context, file CgroupControlFile) (cgroup, error) {
	if c.Kernel.Cgroup2FS().EverMounted() {
		if cg, err := c.Kernel.Cgroup2FS().FindCgroup(ctx, file.Path); err == nil {
			return cg, nil
		}
	}
	return c.findCgroup(ctx, file)
}

// ReadControlFiles is an RPC stub for batch-reading cgroupfs control files.
func (c *Cgroups) ReadControlFiles(args *CgroupsReadArgs, out *CgroupsResults) error {
	ctx := c.Kernel.SupervisorContext()
	for _, arg := range args.Args {
		cg, err := c.resolveCgroup(ctx, arg.File)
		if err != nil {
			out.Results = append(out.Results, newError(err))
			continue
		}

		val, err := cg.ReadControl(ctx, arg.File.Name)
		if err != nil {
			out.Results = append(out.Results, newError(err))
		} else {
			out.Results = append(out.Results, newValue(val))
		}
	}

	return nil
}

// CgroupsWriteArg represents the arguments for a single write command.
type CgroupsWriteArg = controlapi.CgroupsWriteArg

// CgroupsWriteArgs represents the lust of arguments for a batched write command.
type CgroupsWriteArgs = controlapi.CgroupsWriteArgs

// WriteControlFiles is an RPC stub for batch-writing cgroupfs control files.
func (c *Cgroups) WriteControlFiles(args *CgroupsWriteArgs, out *CgroupsResults) error {
	ctx := c.Kernel.SupervisorContext()

	for _, arg := range args.Args {
		cg, err := c.resolveCgroup(ctx, arg.File)
		if err != nil {
			out.Results = append(out.Results, newError(err))
			continue
		}

		err = cg.WriteControl(ctx, arg.File.Name, arg.Value)
		if err != nil {
			out.Results = append(out.Results, newError(err))
		} else {
			out.Results = append(out.Results, newValue(""))
		}
	}
	return nil
}
