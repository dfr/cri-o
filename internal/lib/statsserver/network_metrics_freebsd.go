package statsserver

import (
	"encoding/json"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	"os/exec"

	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/log"
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

func (ss *StatsServer) GenerateNetworkMetrics(sb *sandbox.Sandbox) []*types.Metric {
	var metrics []*types.Metric

	args := []string{"-bi", "-n", "--libxo", "json"}
	if !sb.HostNetwork() {
		args = append(args, "-j", sb.ID())
	}
	cmd := exec.Command("netstat", args...)
	out, err := cmd.Output()
	if err != nil {
		log.Errorf(ss.ctx, "failed to get network stats from %s: %w", sb.ID(), err)
		return nil
	}
	stats := Netstat{}
	if err := json.Unmarshal(out, &stats); err != nil {
		log.Errorf(ss.ctx, "failed to decode network stats from %s: %w", sb.ID(), err)
		return nil
	}

	for _, attrs := range stats.Statistics.Interface {
		networkMetrics := generateSandboxNetworkMetrics(sb, &attrs)
		metrics = append(metrics, networkMetrics...)
	}

	return metrics
}

func generateSandboxNetworkMetrics(sb *sandbox.Sandbox, attr *NetstatAddress) []*types.Metric {
	// Each link can have multiple entries for different address
	// families. These are summarised in the one which represents the
	// link-layer - this one has stats which sum all the address families on
	// the interface and we can detect it by the presence of an mtu field.
	if attr == nil || attr.Mtu == 0 {
		return []*types.Metric{}
	}

	networkMetrics := []*containerMetric{
		{
			desc: containerNetworkReceiveBytesTotal,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      attr.ReceivedBytes,
					labels:     []string{attr.Name},
					metricType: types.MetricType_COUNTER,
				}}
			},
		}, {
			desc: containerNetworkReceivePacketsTotal,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      attr.ReceivedPackets,
					labels:     []string{attr.Name},
					metricType: types.MetricType_COUNTER,
				}}
			},
		}, {
			desc: containerNetworkReceivePacketsDroppedTotal,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      attr.DroppedPackets,
					labels:     []string{attr.Name},
					metricType: types.MetricType_COUNTER,
				}}
			},
		}, {
			desc: containerNetworkReceiveErrorsTotal,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      attr.ReceivedErrors,
					labels:     []string{attr.Name},
					metricType: types.MetricType_COUNTER,
				}}
			},
		}, {
			desc: containerNetworkTransmitBytesTotal,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      attr.SentBytes,
					labels:     []string{attr.Name},
					metricType: types.MetricType_COUNTER,
				}}
			},
		}, {
			desc: containerNetworkTransmitPacketsTotal,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      attr.SentPackets,
					labels:     []string{attr.Name},
					metricType: types.MetricType_COUNTER,
				}}
			},
		}, {
			desc: containerNetworkTransmitErrorsTotal,
			valueFunc: func() metricValues {
				return metricValues{{
					value:      attr.SentErrors,
					labels:     []string{attr.Name},
					metricType: types.MetricType_COUNTER,
				}}
			},
		},
	}

	return computeSandboxMetrics(sb, networkMetrics)
}
