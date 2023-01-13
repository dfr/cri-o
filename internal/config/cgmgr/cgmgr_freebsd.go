package cgmgr

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

type CgroupManager interface {
	// String returns the name of the cgroup manager (either cgroupfs or systemd)
	Name() string
	// IsSystemd returns whether it is a systemd cgroup manager
	IsSystemd() bool
	// ContainerCgroupPath takes arguments sandbox parent cgroup and container ID and returns
	// the cgroup path for that containerID. If parentCgroup is empty, it
	// uses the default parent for that particular manager
	ContainerCgroupPath(string, string) string
	// cgroup parent, cgroup path, minimum container memory, error
	SandboxCgroupPath(string, string, int64) string
	// RemoveSandboxCgroup takes the sandbox parent, and sandbox ID.
	// It removes the cgroup for that sandbox, which is useful when spoofing an infra container
	RemoveSandboxCgroup(sbParent, containerID string) error
	// ContainerCgroupStats takes the sandbox parent, and container ID.
	// It creates a new cgroup if one does not already exist.
	// It returns the cgroup stats for that container.
	ContainerCgroupStats(sbParent, containerID string) (*CgroupStats, error)
}

type NullCgroupManager struct{}

func getRacct(filter string) (map[string]uint64, error) {
	bp, err := syscall.ByteSliceFromString(filter)
	if err != nil {
		return nil, err
	}
	var buf [1024]byte
	_, _, errno := syscall.Syscall6(syscall.SYS_RCTL_GET_RACCT,
		uintptr(unsafe.Pointer(&bp[0])),
		uintptr(len(bp)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("error calling rctl_get_racct with filter %s: %v", errno)
	}
	len := bytes.IndexByte(buf[:], byte(0))
	entries := strings.Split(string(buf[:len]), ",")
	res := make(map[string]uint64)
	for _, entry := range entries {
		key, valstr, _ := strings.Cut(entry, "=")
		val, err := strconv.ParseUint(valstr, 10, 0)
		if err != nil {
			logrus.Warnf("unexpected rctl entry, ignoring: %s", entry)
		}
		res[key] = val
	}
	return res, nil
}

func InitializeCgroupManager(cgroupManager string) (CgroupManager, error) {
	return nil, errors.New("not implemented yet")
}

// New creates a new CgroupManager with defaults
func New() CgroupManager {
	return &NullCgroupManager{}
}

func SetCgroupManager(cgroupManager string) (CgroupManager, error) {
	return &NullCgroupManager{}, nil
}

// MoveProcessToContainerCgroup moves process to the container cgroup
func MoveProcessToContainerCgroup(containerPid, commandPid int) error {
	return nil
}

// VerifyMemoryIsEnough verifies that the cgroup memory limit is above a specified minimum memory limit.
func VerifyMemoryIsEnough(memoryLimit, containerMinMemory int64) error {
	return nil
}

func (*NullCgroupManager) Name() string {
	return "none"
}

func (*NullCgroupManager) IsSystemd() bool {
	return false
}

func (*NullCgroupManager) ContainerCgroupPath(string, string) string {
	return ""
}

func (*NullCgroupManager) SandboxCgroupPath(string, string, int64) string {
	return ""
}

func (*NullCgroupManager) ContainerCgroupStats(sbParent, containerID string) (*CgroupStats, error) {
	stats := &CgroupStats{
		SystemNano: time.Now().UnixNano(),
	}

	entries, err := getRacct("jail:" + sbParent)
	if err != nil {
		return nil, fmt.Errorf("unable to read accounting for %s: %w", containerID, err)
	}

	stats.CPU = &CPUStats{}
	if val, ok := entries["cputime"]; ok {
		// Cumulative CPU time, in seconds. XXX add 1 to make
		// metrics-server happy - it treats zero cpu usage as a failure
		stats.CPU.TotalUsageNano = val*1000000000 + 1
	}
	stats.Memory = &MemoryStats{}
	if val, ok := entries["memoryuse"]; ok {
		stats.Memory.WorkingSetBytes = val
		stats.Memory.RssBytes = val
	}
	if val, ok := entries["vmemoryuse"]; ok {
		stats.Memory.MaxUsage = val
	}

	return stats, nil
}

func (*NullCgroupManager) RemoveSandboxCgroup(sbParent, containerID string) error {
	return nil
}
