package statsserver

import (
	types "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/cri-o/cri-o/internal/lib/stats"
	"github.com/cri-o/cri-o/internal/oci"
)

func generateContainerMemoryMetrics(ctr *oci.Container, mem *stats.MemoryStats) []*types.Metric {
	if mem == nil {
		return []*types.Metric{}
	}

	memoryMetrics := []*containerMetric{
		{
			desc: containerMemoryRss,
			valueFunc: func() metricValues {
				return metricValues{{value: mem.Usage.Usage, metricType: types.MetricType_GAUGE}}
			},
		},
		{
			desc: containerMemoryUsageBytes,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      mem.Usage.Usage,
					metricType: types.MetricType_GAUGE,
				}}
			},
		},
		{
			desc: containerMemoryMaxUsageBytes,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      mem.Usage.MaxUsage,
					metricType: types.MetricType_GAUGE,
				}}
			},
		},
		{
			desc: containerMemoryWorkingSetBytes,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      mem.Usage.Usage,
					metricType: types.MetricType_GAUGE,
				}}
			},
		},
	}

	return computeContainerMetrics(ctr, memoryMetrics)
}
