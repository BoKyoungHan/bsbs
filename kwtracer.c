#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/pid.h>

#define READ 0
#define WRITE 1

#pragma pack(4)
struct data_t {
	char comm[TASK_COMM_LEN];
	char disk_name[DISK_NAME_LEN];
	u64 sector;
	u64 len;
	u64 rwflag;
	u64 ppid;
	u64 ts;
	u32 pid;
};
BPF_PERF_OUTPUT(events);

void trace_req_start(struct pt_regs *ctx, struct request *req)
{
	struct data_t data = {};
	
	events.perf_submit(ctx,&data,sizeof(data));
        return ;
}


void trace_req_completion(struct pt_regs *ctx, struct request *req)
{
	struct data_t data = {};
	struct gendisk *rq_disk = req->rq_disk;
	bpf_probe_read(&data.disk_name, sizeof(data.disk_name), rq_disk->disk_name);
	
	u64 ppid;
	u32 pid; // = bpf_get_current_pid_tgid();
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	//pid = task->pid;
	pid = bpf_get_current_pid_tgid();
	ppid = task->real_parent->pid;

#ifdef REQ_WRITE
        data.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
        data.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
        data.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif
	data.sector = req->__sector;
	data.len = req->__data_len;
	data.pid = pid;
	data.ppid = ppid;
	data.ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	events.perf_submit(ctx, &data, sizeof(data));
	return ;
}





