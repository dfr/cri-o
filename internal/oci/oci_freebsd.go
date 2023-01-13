package oci

import (
	"context"
	"os"
	"syscall"

	"github.com/cri-o/cri-o/internal/config/jail"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const InfraContainerName = "POD"

func (r *Runtime) createContainerPlatform(c *Container, cgroupParent string, pid int) error {
	return nil
}

func sysProcAttrPlatform() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

func newPipe() (*os.File, *os.File, error) {
	return os.Pipe()
}

func (r *runtimeOCI) containerStats(ctr *Container, jailName string) (*types.ContainerStats, error) {
	stats := &types.ContainerStats{
		Attributes: ctr.CRIAttributes(),
	}

	if ctr.Spoofed() {
		return stats, nil
	}

	if err := jail.PopulateContainerStats(jailName, stats); err != nil {
		return nil, err
	}

	return stats, nil
}

// CleanupConmonCgroup cleans up conmon's group when using cgroupfs.
func (c *Container) CleanupConmonCgroup(ctx context.Context) {
}

// SetSeccompProfilePath sets the seccomp profile path
func (c *Container) SetSeccompProfilePath(pp string) {
}

// SeccompProfilePath returns the seccomp profile path
func (c *Container) SeccompProfilePath() string {
	return ""
}
