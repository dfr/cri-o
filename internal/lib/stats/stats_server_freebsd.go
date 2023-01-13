//go:build freebsd
// +build freebsd

package statsserver

import (
	"context"
	"slices"

	"github.com/cri-o/cri-o/internal/config/cgmgr"
	"github.com/cri-o/cri-o/internal/config/jail"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/log"
	"github.com/cri-o/cri-o/internal/oci"
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
	if !sb.HostNetwork() {
		if err := jail.PopulateNetworkUsage(sb.ID(), sandboxStats); err != nil {
			logrus.Errorf("Error adding network stats for sandbox %s: %v", sb.ID(), err)
		}
	}

	containersList := sb.Containers().List()
	containerStats := make([]*types.ContainerStats, 0, len(containersList))
	containerMetrics := make([]*types.ContainerMetrics, 0, len(containersList))

	for _, c := range sb.Containers().List() {
		if c.StateNoLock().Status == oci.ContainerStateStopped {
			continue
		}

		cgstats, err := ss.Runtime().ContainerStats(context.TODO(), c, ss.jailName(c, sb))
		if err != nil {
			logrus.Errorf("Error getting container stats %s: %v", c.ID(), err)

			continue
		}
		// Convert cgroups stats to CRI stats.
		cStats := containerCRIStats(cgstats, c, cgstats.SystemNano)
		ss.populateWritableLayer(cStats, c)

		if oldcStats, ok := ss.ctrStats[c.ID()]; ok {
			updateUsageNanoCores(oldcStats.Cpu, cStats.Cpu)
		}

		containerStats = append(containerStats, cStats)

		// Convert cgroups stats to CRI metrics.
		cMetrics := ss.containerMetricsFromCgStats(sb, c, cgstats)
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

	return ss.containerMetricsFromCgStats(sb, c, cgstats)
}

func (ss *StatsServer) containerMetricsFromCgStats(sb *sandbox.Sandbox, c *oci.Container, cgstats *cgmgr.CgroupStats) *types.ContainerMetrics {
	var metrics []*types.Metric

	for _, m := range ss.Config().IncludedPodMetrics {
		switch m {
		case "cpu":
			if cpuMetrics := generateSandboxCPUMetrics(sb, cgstats.CPU); cpuMetrics != nil {
				metrics = append(metrics, cpuMetrics...)
			}
		case "memory":
			if memoryMetrics := generateSandboxMemoryMetrics(sb, cgstats.Memory); memoryMetrics != nil {
				metrics = append(metrics, memoryMetrics...)
			}
		case "network":
			continue // Network metrics are collected at the pod level only.
		default:
			log.Warnf(ss.ctx, "Unknown metric: %s", m)
		}
	}

	return &types.ContainerMetrics{
		ContainerId: c.ID(),
		Metrics:     metrics,
	}
}

func containerCRIStats(stats *cgmgr.CgroupStats, ctr *oci.Container, systemNano int64) *types.ContainerStats {
	criStats := &types.ContainerStats{
		Attributes: ctr.CRIAttributes(),
	}
	criStats.Cpu = criCPUStats(stats.CPU, systemNano)
	criStats.Memory = criMemStats(stats.Memory, systemNano)
	criStats.Swap = criSwapStats(stats.Memory, systemNano)

	return criStats
}

func criCPUStats(cpuStats *cgmgr.CPUStats, systemNano int64) *types.CpuUsage {
	return &types.CpuUsage{
		Timestamp:            systemNano,
		UsageCoreNanoSeconds: &types.UInt64Value{Value: cpuStats.TotalUsageNano},
	}
}

func criMemStats(memStats *cgmgr.MemoryStats, systemNano int64) *types.MemoryUsage {
	return &types.MemoryUsage{
		Timestamp:       systemNano,
		WorkingSetBytes: &types.UInt64Value{Value: memStats.WorkingSetBytes},
		RssBytes:        &types.UInt64Value{Value: memStats.RssBytes},
		PageFaults:      &types.UInt64Value{Value: memStats.PageFaults},
		MajorPageFaults: &types.UInt64Value{Value: memStats.MajorPageFaults},
		UsageBytes:      &types.UInt64Value{Value: memStats.Usage},
		AvailableBytes:  &types.UInt64Value{Value: memStats.AvailableBytes},
	}
}

func criSwapStats(memStats *cgmgr.MemoryStats, systemNano int64) *types.SwapUsage {
	return &types.SwapUsage{
		Timestamp:          systemNano,
		SwapUsageBytes:     &types.UInt64Value{Value: memStats.SwapUsage},
		SwapAvailableBytes: &types.UInt64Value{Value: memStats.SwapLimit - memStats.SwapUsage},
	}
}
