package statsserver

import (
	"fmt"
	"time"

	types "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/cri-o/cri-o/internal/lib/stats"
	"github.com/cri-o/cri-o/internal/oci"
)

func generateContainerCPUMetrics(ctr *oci.Container, cpu *stats.CpuStats) []*types.Metric {
	if cpu == nil {
		return []*types.Metric{}
	}

	cpuMetrics := []*containerMetric{
		{
			desc: containerCpuUsageSecondsTotal,
			valueFunc: func() metricValues {
				if len(cpu.CpuUsage.PercpuUsage) == 0 && cpu.CpuUsage.TotalUsage > 0 {
					return metricValues{{
						value:      cpu.CpuUsage.TotalUsage / uint64(time.Second),
						labels:     []string{"total"},
						metricType: types.MetricType_COUNTER,
					}}
				}

				metricValues := make(metricValues, 0, len(cpu.CpuUsage.PercpuUsage))
				for i, value := range cpu.CpuUsage.PercpuUsage {
					if value > 0 {
						metricValues = append(metricValues, metricValue{
							value:      value / uint64(time.Second),
							labels:     []string{fmt.Sprintf("cpu%02d", i)},
							metricType: types.MetricType_COUNTER,
						})
					}
				}

				return metricValues
			},
		},
	}

	return computeContainerMetrics(ctr, cpuMetrics)
}
