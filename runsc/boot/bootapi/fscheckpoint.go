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

package bootapi

import (
	"fmt"
	"path"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	AnnotationFSCheckpointPrefix = "dev.gvisor.internal.fscheckpoint."

	// AnnotationFSCheckpointEnable indicates whether files under /proc/gvisor
	// should be present in the container to allow the workload to trigger a
	// filesystem checkpoint.
	AnnotationFSCheckpointEnable = AnnotationFSCheckpointPrefix + "enable"

	// AnnotationFSCheckpointPath is the path to the directory where the
	// filesystem checkpoint files will be created. When present, it allows for
	// the workload running inside to trigger a filesystem checkpoint without
	// having to use the runsc CLI.
	AnnotationFSCheckpointPath = AnnotationFSCheckpointPrefix + "path"

	// AnnotationFSCheckpointResume indicates whether the sandbox should
	// continue running after filesystem checkpoint saving triggered via
	// /proc/gvisor. Optional, defaults to false.
	AnnotationFSCheckpointResume = AnnotationFSCheckpointPrefix + "resume"

	// AnnotationFSCheckpointDirect indicates whether filesystem checkpoint
	// I/Os triggered via /proc/gvisor should use O_DIRECT. Optional, defaults
	// to false.
	AnnotationFSCheckpointDirect = AnnotationFSCheckpointPrefix + "direct"

	// AnnotationFSCheckpointPaths is a comma-separated list of paths inside the
	// containers to save. Optional.
	AnnotationFSCheckpointPaths = AnnotationFSCheckpointPrefix + "paths"
)

// GetAnnotationFSCheckpointPath returns the filesystem checkpoint path
// specified in the container annotation. Return empty string if no annotation
// is specified.
func GetAnnotationFSCheckpointPath(spec *specs.Spec) string {
	return spec.Annotations[AnnotationFSCheckpointPath]
}

// GetAnnotationFSCheckpointDirect returns true if filesystem checkpoint I/O
// controlled by the containing annotation should use O_DIRECT.
func GetAnnotationFSCheckpointDirect(spec *specs.Spec) bool {
	return specutils.AnnotationToBool(spec, AnnotationFSCheckpointDirect)
}

// ParseFSCheckpointPaths parses a comma-separated list of container:path
// checkpoint targets.
func ParseFSCheckpointPaths(val string) ([]checkpoint.ResourceID, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return nil, nil
	}
	var paths []checkpoint.ResourceID
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var c, p string
		subparts := strings.SplitN(part, ":", 2)
		if len(subparts) == 1 {
			p = strings.TrimSpace(subparts[0])
		} else {
			c = strings.TrimSpace(subparts[0])
			p = strings.TrimSpace(subparts[1])
		}
		if p == "" {
			return nil, fmt.Errorf("empty path in fscheckpoint paths: %q", val)
		}
		if p != fscheckpoint.AllTmpfsPath && (!path.IsAbs(p) || path.Clean(p) != p) {
			return nil, fmt.Errorf("checkpoint path must be an absolute, clean path or %q, got: %q", fscheckpoint.AllTmpfsPath, p)
		}
		paths = append(paths, checkpoint.ResourceID{ContainerName: c, Path: p})
	}
	return paths, nil
}
