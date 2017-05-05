#ifndef __GETTIMEOFDAY_BPF_H
#define __GETTIMEOFDAY_BPF_H

#include <linux/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct gettimeofday_event_t {
	__u64 timestamp;
	__u64 cpu;
	__u64 pid;
	char comm[TASK_COMM_LEN];
};

#endif
