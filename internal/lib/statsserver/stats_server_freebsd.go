//go:build freebsd
// +build freebsd

package statsserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"time"

	"github.com/cri-o/cri-o/internal/config/jail"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/lib/stats"
	"github.com/cri-o/cri-o/internal/log"
	"github.com/cri-o/cri-o/internal/oci"
	"github.com/cri-o/cri-o/pkg/config"
	"github.com/sirupsen/logrus"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// updateSandbox updates the StatsServer's entry for this sandbox, as well as each child container.
// It first populates the stats from the CgroupParent, then calculates network usage, updates
// each of its children container stats by calling into the runtime, and finally calculates the CPUNanoCores.
func (ss *StatsServer) updateSandbox(sb *sandbox.Sandbox) *types.PodSandboxStats {
	if sb == nil {
		return nil
	}

	// Sandbox metrics are to fulfill the CRI metrics endpoint.
	sandboxMetrics, exists := ss.sboxMetrics[sb.ID()]
	if !exists {
		sandboxMetrics = NewSandboxMetrics(sb)
	}

	// Sandbox stats are to fulfill the Kubelet's /stats/summary endpoint.
	sandboxStats := &types.PodSandboxStats{
		Attributes: &types.PodSandboxAttributes{
			Id:          sb.ID(),
			Labels:      sb.Labels(),
			Metadata:    sb.Metadata(),
			Annotations: sb.Annotations(),
		},
		Linux: &types.LinuxPodSandboxStats{},
	}

	if err := jail.PopulateSandboxStats(sb.ID(), sandboxStats); err != nil {
		logrus.Errorf("Error getting sandbox stats %s: %v", sb.ID(), err)
	}

	// Network metrics are collected at pod level only.
	if slices.Contains(ss.Config().EnabledPodMetrics(), config.NetworkMetrics) {
		podMetrics := ss.GenerateNetworkMetrics(sb)
		sandboxMetrics.metric.Metrics = podMetrics
	}

	containersList := sb.Containers().List()
	containerStats := make([]*types.ContainerStats, 0, len(containersList))
	containerMetrics := make([]*types.ContainerMetrics, 0, len(containersList))

	for _, c := range containersList {
		if c.StateNoLock().Status == oci.ContainerStateStopped {
			continue
		}

		ctrStats, err := ss.Runtime().ContainerStats(context.TODO(), c, ss.jailName(c, sb))
		if err != nil {
			logrus.Errorf("Error getting container stats %s: %v", c.ID(), err)

			continue
		}
		// Convert cgroups stats to CRI stats.
		cStats := containerCRIStats(ctrStats, c, ctrStats.SystemNano)
		ss.populateWritableLayer(cStats, c)

		if oldcStats, ok := ss.ctrStats[c.ID()]; ok {
			updateUsageNanoCores(oldcStats.GetCpu(), cStats.GetCpu())
		}

		containerStats = append(containerStats, cStats)

		// Convert cgroups stats to CRI metrics.
		cMetrics := ss.containerMetricsFromContainerStats(sb, c, ctrStats)
		containerMetrics = append(containerMetrics, cMetrics)
	}

	sandboxStats.Linux.Containers = containerStats
	sandboxMetrics.metric.ContainerMetrics = containerMetrics

	if old, ok := ss.sboxStats[sb.ID()]; ok {
		updateUsageNanoCores(old.Linux.Cpu, sandboxStats.Linux.Cpu)
	}

	ss.sboxStats[sb.ID()] = sandboxStats
	ss.sboxMetrics[sb.ID()] = sandboxMetrics

	return sandboxStats
}

func (ss *StatsServer) jailName(c *oci.Container, sb *sandbox.Sandbox) string {
	infra := sb.InfraContainer()
	if !infra.Spoofed() && c.ID() != sb.ID() {
		// Containers in the pod are children of the infra container
		return sb.ID() + "." + c.ID()
	}
	return c.ID()
}

// updateContainerStats calls into the runtime handler to update the container
// stats, as well as populates the writable layer by calling into the container
// storage.  If this container already existed in the stats server, the CPU nano
// cores are calculated as well.
func (ss *StatsServer) updateContainerStats(c *oci.Container, sb *sandbox.Sandbox) *types.ContainerStats {
	if c == nil || sb == nil {
		return nil
	}
	if c.StateNoLock().Status == oci.ContainerStateStopped {
		return nil
	}
	cgstats, err := ss.Runtime().ContainerStats(context.TODO(), c, ss.jailName(c, sb))
	if err != nil {
		logrus.Errorf("Error getting container stats %s: %v", c.ID(), err)

		return nil
	}

	cStats := containerCRIStats(cgstats, c, cgstats.SystemNano)
	ss.populateWritableLayer(cStats, c)

	if oldcStats, ok := ss.ctrStats[c.ID()]; ok {
		updateUsageNanoCores(oldcStats.Cpu, cStats.Cpu)
	}

	ss.ctrStats[c.ID()] = cStats

	return cStats
}

func (ss *StatsServer) populateNetworkUsage(sbStats *types.PodSandboxStats, sb *sandbox.Sandbox) error {
	// FIXME: get the default interface name from the CNI somehow
	args := []string{"-bi", "-n", "--libxo", "json"}
	if !sb.HostNetwork() {
		args = append(args, "-j", sb.ID())
	}
	cmd := exec.Command("netstat", args...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get network stats from %s: %w", sb.ID(), err)
	}
	stats := Netstat{}
	if err := json.Unmarshal(out, &stats); err != nil {
		return err
	}

	sbStats.Linux.Network = &types.NetworkUsage{}

	// Find the link stats. Each link can have multiple entries for
	// different address families. These are summarised in the one which
	// represents the link-layer - this one has stats which sum all the
	// address families on the interface and we can detect it by the
	// presents of an mtu field.
	i := 0
	for _, ifAddr := range stats.Statistics.Interface {
		if ifAddr.Mtu > 0 {
			iface, err := linkToInterface(&ifAddr)
			if err != nil {
				log.Errorf(ss.ctx, "Failed to %v for pod %s", err, sb.ID())

				continue
			}
			// TODO FIXME or DefaultInterfaceName?
			if i == 0 {
				sbStats.Linux.Network.DefaultInterface = iface
			} else {
				sbStats.Linux.Network.Interfaces = append(sbStats.Linux.Network.Interfaces, iface)
			}
			i++
		}
	}

	return nil
}

// metricsForPodSandbox is an internal, non-locking version of MetricsForPodSandbox
// that returns (and occasionally gathers) the metrics for the given sandbox.
// Note: the caller must hold the lock on the StatsServer
func (ss *StatsServer) metricsForPodSandbox(sb *sandbox.Sandbox) *SandboxMetrics {
	if ss.collectionPeriod == 0 {
		return ss.updatePodSandboxMetrics(sb)
	}

	if sboxMetrics, ok := ss.sboxMetrics[sb.ID()]; ok {
		return sboxMetrics
	}
	// Cache miss, try again.
	return ss.updatePodSandboxMetrics(sb)
}

// updatePodSandboxMetrics updates the sandbox metrics for the given sandbox.
// If the sandbox is not found, it creates a new entry in the map.
// Note: caller must hold the lock on the StatsServer.
func (ss *StatsServer) updatePodSandboxMetrics(sb *sandbox.Sandbox) *SandboxMetrics {
	if sb == nil {
		return nil
	}

	sm, exists := ss.sboxMetrics[sb.ID()]
	if !exists {
		sm = NewSandboxMetrics(sb)
	}
	// Network metrics are collected at the pod level.
	if slices.Contains(ss.Config().IncludedPodMetrics, "network") {
		podMetrics := ss.GenerateNetworkMetrics(sb)
		sm.metric.Metrics = podMetrics
	}

	containersList := sb.Containers().List()
	containerMetrics := make([]*types.ContainerMetrics, 0, len(containersList))

	for _, c := range containersList {
		// Skip if the container is stopped.
		if c.StateNoLock().Status == oci.ContainerStateStopped {
			continue
		}

		cMetrics := ss.GenerateSandboxContainerMetrics(sb, c, sm)
		containerMetrics = append(containerMetrics, cMetrics)
	}

	sm.metric.ContainerMetrics = containerMetrics
	ss.sboxMetrics[sb.ID()] = sm

	return sm
}

// GenerateSandboxContainerMetrics generates a list of metrics for the specified sandbox
// containers by collecting metrics from the cgroup based on the included pod metrics,
// except for network metrics, which are collected at the pod level.
func (ss *StatsServer) GenerateSandboxContainerMetrics(sb *sandbox.Sandbox, c *oci.Container, sm *SandboxMetrics) *types.ContainerMetrics {
	cgstats, err := ss.Runtime().ContainerStats(ss.ctx, c, sb.ID())
	if err != nil || cgstats == nil {
		log.Errorf(ss.ctx, "Error getting sandbox stats %s: %v", sb.ID(), err)

		return nil
	}

	return ss.containerMetricsFromContainerStats(sb, c, cgstats)
}

func (ss *StatsServer) containerMetricsFromContainerStats(sb *sandbox.Sandbox, c *oci.Container, cgroupStats *stats.CgroupStats) *types.ContainerMetrics {
	metrics := computeContainerMetrics(c, []*containerMetric{{
		desc: containerLastSeen,
		valueFunc: func() metricValues {
			return metricValues{{
				value:      uint64(time.Now().Unix()),
				metricType: types.MetricType_GAUGE,
			}}
		},
	}})

	for _, m := range ss.Config().EnabledPodMetrics() {
		switch m {
		case config.CPUMetrics:
			if cpuMetrics := generateContainerCPUMetrics(c, &cgroupStats.CpuStats); cpuMetrics != nil {
				metrics = append(metrics, cpuMetrics...)
			}
		case config.HugetlbMetrics:
		case config.DiskMetrics:
		case config.DiskIOMetrics:
			continue
		case config.MemoryMetrics:
			if memoryMetrics := generateContainerMemoryMetrics(c, &cgroupStats.MemoryStats); memoryMetrics != nil {
				metrics = append(metrics, memoryMetrics...)
			}
		case config.OOMMetrics:
			continue
		case config.NetworkMetrics:
			continue // Network metrics are collected at the pod level only.
		case config.ProcessMetrics:
		case config.SpecMetrics:
		case config.PressureMetrics:
			continue
		default:
			log.Warnf(ss.ctx, "Unknown metric: %s", m)
		}
	}

	return &types.ContainerMetrics{
		ContainerId: c.ID(),
		Metrics:     metrics,
	}
}

// linkToInterface translates information found from the netlink package
// into CRI the NetworkInterfaceUsage structure.
func linkToInterface(ifAddr *NetstatAddress) (*types.NetworkInterfaceUsage, error) {
	return &types.NetworkInterfaceUsage{
		Name:     ifAddr.Name,
		RxBytes:  &types.UInt64Value{Value: ifAddr.ReceivedBytes},
		RxErrors: &types.UInt64Value{Value: ifAddr.ReceivedErrors},
		TxBytes:  &types.UInt64Value{Value: ifAddr.SentBytes},
		TxErrors: &types.UInt64Value{Value: ifAddr.SentErrors},
	}, nil
}

func containerCRIStats(stats *stats.CgroupStats, ctr *oci.Container, systemNano int64) *types.ContainerStats {
	criStats := &types.ContainerStats{
		Attributes: ctr.CRIAttributes(),
	}
	criStats.Cpu = criCPUStats(&stats.CpuStats, systemNano)
	criStats.Memory = criMemStats(&stats.MemoryStats, systemNano)
	criStats.Swap = criSwapStats(&stats.MemoryStats, systemNano)

	return criStats
}

func criCPUStats(cpuStats *stats.CpuStats, systemNano int64) *types.CpuUsage {
	return &types.CpuUsage{
		Timestamp:            systemNano,
		UsageCoreNanoSeconds: &types.UInt64Value{Value: cpuStats.CpuUsage.TotalUsage},
	}
}

func criMemStats(memStats *stats.MemoryStats, systemNano int64) *types.MemoryUsage {
	return &types.MemoryUsage{
		Timestamp:       systemNano,
		WorkingSetBytes: &types.UInt64Value{Value: memStats.Usage.Usage},
	}
}

func criSwapStats(memStats *stats.MemoryStats, systemNano int64) *types.SwapUsage {
	return &types.SwapUsage{
		Timestamp: systemNano,
	}
}
