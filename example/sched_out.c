#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>

#pragma pack(4)
struct data_t {
	u64 pid;
	long long time;
	char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

struct p_schedule_out_info{
        long long start;
        long long end;
};

BPF_HASH(p_schedule_out_info_map, u64 , struct p_schedule_out_info);

void startio_entry(struct pt_regs *ctx, struct request *req){
        long long start_time = bpf_ktime_get_ns();
	
	// get pid	
	u64 pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	pid = task->pid;

	struct p_schedule_out_info p_schedule_out_info = {
                .start = start_time,
                .end = 0
        };

        p_schedule_out_info_map.update(&pid, &p_schedule_out_info);
        return ;
}

void endio_entry(struct pt_regs *ctx, struct request *req){
	//u64 pid = bpf_get_current_pid_tgid();
	u64 pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	pid = task->pid;

	long long start_time = 0;
        long long end_time = bpf_ktime_get_ns();

        struct p_schedule_out_info* p_schedule_out_info;

        p_schedule_out_info = p_schedule_out_info_map.lookup(&pid);
        if(!p_schedule_out_info){
                bpf_trace_printk("Pid is not registered at p_schdeuld_out_info_map\n");
                return ;
        }

        p_schedule_out_info->end = end_time;
	start_time = p_schedule_out_info->start;

	struct data_t data = {};
	data.pid = pid;
	data.time = end_time-start_time;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	events.perf_submit(ctx,&data,sizeof(data));

        return ;
}
