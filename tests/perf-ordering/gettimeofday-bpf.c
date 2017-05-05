#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>

#include "gettimeofday-bpf.h"

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/gettimeofday_event") gettimeofday_event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
};

SEC("kprobe/sys_newuname")
int kprobe__sys_newuname(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u32 cpu = bpf_get_smp_processor_id();

	// output
	struct gettimeofday_event_t evt = {
		.timestamp = bpf_ktime_get_ns(),
		.cpu = cpu,
		.pid = pid,
	};
	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

	int ret = bpf_perf_event_output(ctx, &gettimeofday_event, cpu, &evt, sizeof(evt));

	char msg[] = "uname %d\n";
	bpf_trace_printk(msg, sizeof(msg), ret);
	//bpf_trace_printk("uname", 5);
	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by gobpf-elf-loader to set the current
// running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
