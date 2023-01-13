package jail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type Netstat struct {
	Statistics NetstatInterface `json:"statistics"`
}

type NetstatInterface struct {
	Interface []NetstatAddress `json:"interface"`
}

type NetstatAddress struct {
	Name    string `json:"name"`
	Flags   string `json:"flags"`
	Mtu     int    `json:"mtu"`
	Network string `json:"network"`
	Address string `json:"address"`

	ReceivedPackets uint64 `json:"received-packets"`
	ReceivedBytes   uint64 `json:"received-bytes"`
	ReceivedErrors  uint64 `json:"received-errors"`

	SentPackets uint64 `json:"sent-packets"`
	SentBytes   uint64 `json:"sent-bytes"`
	SentErrors  uint64 `json:"send-errors"`

	DroppedPackets uint64 `json:"dropped-packets"`

	Collisions uint64 `json:"collisions"`
}

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

func PopulateContainerStats(jailName string, stats *types.ContainerStats) error {
	entries, err := getRacct("jail:" + jailName)
	if err != nil {
		return fmt.Errorf("unable to read accounting for %s: %w", jailName, err)
	}

	now := time.Now().UnixNano()
	stats.Cpu = &types.CpuUsage{
		Timestamp:            now,
		UsageNanoCores:       &types.UInt64Value{},
		UsageCoreNanoSeconds: &types.UInt64Value{},
	}
	if val, ok := entries["cputime"]; ok {
		// Cumulative CPU time, in seconds. XXX add 1 to make
		// metrics-server happy - it treats zero cpu usage as a failure
		stats.Cpu.UsageCoreNanoSeconds.Value = val*1000000000 + 1
	}
	stats.Memory = &types.MemoryUsage{
		Timestamp:       now,
		WorkingSetBytes: &types.UInt64Value{},
		RssBytes:        &types.UInt64Value{},
		PageFaults:      &types.UInt64Value{},
		MajorPageFaults: &types.UInt64Value{},
		UsageBytes:      &types.UInt64Value{},
		AvailableBytes:  &types.UInt64Value{},
	}
	if val, ok := entries["memoryuse"]; ok {
		stats.Memory.WorkingSetBytes.Value = val
		stats.Memory.RssBytes.Value = val
	}
	if val, ok := entries["vmemoryuse"]; ok {
		stats.Memory.UsageBytes.Value = val
	}
	return nil
}

// Caller should pass the name of the sandbox vnet jail
func PopulateSandboxStats(jailName string, sandboxStats *types.PodSandboxStats) error {
	if jailName == "" {
		return nil
	}

	entries, err := getRacct("jail:" + jailName)
	if err != nil {
		return fmt.Errorf("unable to read accounting for %s: %w", jailName, err)
	}

	stats := sandboxStats.Linux

	now := time.Now().UnixNano()
	if val, ok := entries["cputime"]; ok {
		// CPU time, in seconds
		stats.Cpu = &types.CpuUsage{
			Timestamp:            now,
			UsageCoreNanoSeconds: &types.UInt64Value{Value: val * 1000000000},
		}
	}
	if val, ok := entries["memoryuse"]; ok {
		stats.Memory = &types.MemoryUsage{
			Timestamp:       now,
			WorkingSetBytes: &types.UInt64Value{Value: val},
			RssBytes:        &types.UInt64Value{Value: val},
			PageFaults:      &types.UInt64Value{},
			MajorPageFaults: &types.UInt64Value{},
			UsageBytes:      &types.UInt64Value{},
			AvailableBytes:  &types.UInt64Value{},
		}
	}
	if val, ok := entries["maxproc"]; ok {
		stats.Process = &types.ProcessUsage{
			Timestamp:    now,
			ProcessCount: &types.UInt64Value{Value: val},
		}
	}
	return nil
}

func PopulateNetworkUsage(jailName string, sandboxStats *types.PodSandboxStats) error {
	if jailName == "" {
		return nil
	}

	// FIXME: get the default interface name from the CNI somehow
	cmd := exec.Command("netstat", "-j", jailName, "-bi", "-n", "--libxo", "json")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get network stats from %s: %w", jailName, err)
	}
	stats := Netstat{}
	if err := json.Unmarshal(out, &stats); err != nil {
		return err
	}
	sandboxStats.Linux.Network = &types.NetworkUsage{
		Timestamp: time.Now().UnixNano(),
	}

	// Find the link stats. Each link can have multiple entries for
	// different address families. These are summarised in the one which
	// represents the link-layer - this one has stats which sum all the
	// address families on the interface and we can detect it by the
	// presents of an mtu field.
	for _, ifAddr := range stats.Statistics.Interface {
		if ifAddr.Mtu > 0 {
			ifStats := &types.NetworkInterfaceUsage{
				Name:     ifAddr.Name,
				RxBytes:  &types.UInt64Value{Value: ifAddr.ReceivedBytes},
				RxErrors: &types.UInt64Value{Value: ifAddr.ReceivedErrors},
				TxBytes:  &types.UInt64Value{Value: ifAddr.SentBytes},
				TxErrors: &types.UInt64Value{Value: ifAddr.SentErrors},
			}
			if ifAddr.Name == "eth0" {
				sandboxStats.Linux.Network.DefaultInterface = ifStats
			} else {
				sandboxStats.Linux.Network.Interfaces = append(sandboxStats.Linux.Network.Interfaces, ifStats)
			}
		}
	}
	// Try to always have a DefaultInterface even if we didn't see eth0 -
	// this works around nil pointer dereference problems in kubelet's CRI
	// stats provider.
	if sandboxStats.Linux.Network.DefaultInterface == nil {
		sandboxStats.Linux.Network.DefaultInterface = &types.NetworkInterfaceUsage{
			Name:     "eth0",
			RxBytes:  &types.UInt64Value{},
			RxErrors: &types.UInt64Value{},
			TxBytes:  &types.UInt64Value{},
			TxErrors: &types.UInt64Value{},
		}
	}

	return nil
}
