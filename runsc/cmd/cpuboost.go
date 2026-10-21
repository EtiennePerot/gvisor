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

package cmd

import (
	"context"
	"time"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/sandbox"
)

// CPUBoostEnd implements subcommands.Command for the "cpu-boost-end" command.
// It is started by sandbox.CPUBoost.EndWhenRestored and inherits a hold on
// the lifecycle CPU boost of a sandbox as file descriptor 3.
type CPUBoostEnd struct {
	waitRestore time.Duration
}

// Name implements subcommands.Command.Name.
func (*CPUBoostEnd) Name() string {
	return "cpu-boost-end"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*CPUBoostEnd) Synopsis() string {
	return "end the CPU boost of a sandbox after its restore (internal use only)"
}

// Usage implements subcommands.Command.Usage.
func (*CPUBoostEnd) Usage() string {
	return "cpu-boost-end -wait-restore <timeout> <sandbox id>\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *CPUBoostEnd) SetFlags(f *flag.FlagSet) {
	f.DurationVar(&c.waitRestore, "wait-restore", 0, "wait at most this long for the sandbox to finish restoring")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*CPUBoostEnd) FetchSpec(*config.Config, *flag.FlagSet) (string, *specs.Spec, error) {
	return "", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (c *CPUBoostEnd) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	conf := args[0].(*config.Config)
	id := f.Arg(0)
	cont, err := container.Load(conf.RootDir, container.FullID{SandboxID: id, ContainerID: id}, container.LoadOpts{Exact: true, SkipCheck: true})
	if err != nil {
		// The hold is released when this process exits, and the boost
		// ends with the next operation on the sandbox or its destruction.
		log.Warningf("Loading sandbox %q: %v", id, err)
		return subcommands.ExitFailure
	}
	const holdFD = 3
	boost := sandbox.HeldCPUBoost(conf.RootDir, id, cont.Sandbox.CgroupJSON.Cgroup, holdFD)
	defer boost.End()

	done := make(chan error, 1)
	go func() { done <- cont.Sandbox.WaitRestore() }()
	select {
	case err := <-done:
		if err != nil {
			log.Infof("Waiting for sandbox %q to restore: %v", id, err)
		}
	case <-time.After(c.waitRestore):
		log.Infof("Sandbox %q still restoring after %v", id, c.waitRestore)
	}
	return subcommands.ExitSuccess
}
