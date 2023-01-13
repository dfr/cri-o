package stats

// CpuUsage denotes the usage of a CPU.
// All CPU stats are aggregate since container inception.
type CpuUsage struct {
	// Total CPU time consumed.
	// Units: nanoseconds.
	TotalUsage uint64 `json:"total_usage,omitempty"`
	// Total CPU time consumed per core.
	// Units: nanoseconds.
	PercpuUsage []uint64 `json:"percpu_usage,omitempty"`
	// CPU time consumed per core in kernel mode
	// Units: nanoseconds.
	PercpuUsageInKernelmode []uint64 `json:"percpu_usage_in_kernelmode"`
	// CPU time consumed per core in user mode
	// Units: nanoseconds.
	PercpuUsageInUsermode []uint64 `json:"percpu_usage_in_usermode"`
	// Time spent by tasks of the cgroup in kernel mode.
	// Units: nanoseconds.
	UsageInKernelmode uint64 `json:"usage_in_kernelmode"`
	// Time spent by tasks of the cgroup in user mode.
	// Units: nanoseconds.
	UsageInUsermode uint64 `json:"usage_in_usermode"`
}

type CpuStats struct {
	CpuUsage CpuUsage `json:"cpu_usage,omitempty"`
	//ThrottlingData ThrottlingData `json:"throttling_data,omitempty"`
	//PSI            *PSIStats      `json:"psi,omitempty"`
	//BurstData      BurstData      `json:"burst_data,omitempty"`
}

type MemoryData struct {
	Usage    uint64 `json:"usage,omitempty"`
	MaxUsage uint64 `json:"max_usage,omitempty"`
	Failcnt  uint64 `json:"failcnt"`
	Limit    uint64 `json:"limit"`
}

type MemoryStats struct {
	// usage of memory
	Usage MemoryData `json:"usage,omitempty"`
}

type Stats struct {
	CpuStats    CpuStats    `json:"cpu_stats,omitempty"`
	MemoryStats MemoryStats `json:"memory_stats,omitempty"`
}

type CgroupStats struct {
	Stats

	ProcessStats ProcessStats
	SystemNano   int64
}

type ProcessStats struct {
	Pids            []int
	FileDescriptors uint64
	Sockets         uint64
	Threads         uint64
	ThreadsMax      uint64
	UlimitsSoft     uint64
}
