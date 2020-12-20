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
#include <linux/uio.h>
#include <linux/blk_types.h>
#include <linux/bio.h>
#include <linux/types.h>
#include <linux/mm_types.h>

#define READ 0
#define WRITE 1

#pragma pack(4)
struct data_t {
	u64 address;
	char comm[TASK_COMM_LEN];
	u32 pid;
};

struct writer_t {
	char comm[TASK_COMM_LEN];
	u32 pid;
};


BPF_HASH(page_to_writer_info, u64, struct writer_t);
BPF_HASH(victim_writer_info, int, struct writer_t);

BPF_PERF_OUTPUT(events);
/*void trace_req_start(struct pt_regs *ctx, struct request *req)
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
	
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	u64 ppid = task->real_parent->pid;
	u32 pid = bpf_get_current_pid_tgid();

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
}*/

int trace_do_user_space_write(struct pt_regs *ctx, struct page *page, struct iov_iter *i, unsigned long offset, size_t btyes)
{
	/* init data */
	struct data_t data = {};
	//data.pid = bpf_get_current_pid_tgid();
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	data.pid = task->pid;
	
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	
	/* get writer info */
	struct writer_t writer = {};
	writer.pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&writer.comm, sizeof(writer.comm));
	
	/* get physical page address */
	u64 address = (u64)page;
	
	data.address = address;
	events.perf_submit(ctx, &data, sizeof(data));

	/* update hashmap */
	page_to_writer_info.update(&address, &writer);
		
	return 0;
}

void trace_submit_bio(struct pt_regs *ctx, struct bio *bio) 
{
	struct data_t data = {};
	struct bio_vec *bi_io_vec = bio->bi_io_vec;
	struct page *bv_page = bi_io_vec->bv_page;
	unsigned short bi_max_vecs = bio->bi_vcnt;
	int bi_cnt_counter = bio->__bi_cnt.counter; 
	
	/* lookup victim's writer */
	u64 address = (u64)bv_page;
	struct writer_t *writer = page_to_writer_info.lookup(&address);
		
	
	//bpf_probe_read_str(data.comm, sizeof(data.comm), writer->comm);
	data.pid = writer->pid;
	events.perf_submit(ctx, &data, sizeof(data));
	return ;
}
