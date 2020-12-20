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
	char comm[TASK_COMM_LEN];
	char disk_name[DISK_NAME_LEN];
	unsigned short bi_max_vecs;
	u64 ppid;
	u64 ts;
	unsigned long wb_idx; // writeback start offset
	unsigned long vm_start;
	u32 pid;
};

struct writer_t {
	// TODO: core info
	char comm[TASK_COMM_LEN];
	u32 pid;
};


BPF_HASH(page_to_writer_info, unsigned long, struct writer_t);

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
}

int trace_do_user_space_write(struct pt_regs *ctx, struct page *page, struct iov_iter *i, unsigned long offset, size_t btyes)
{
	struct data_t data = {};
	struct address_space *mapping = page->mapping;

	/* writeback start offset */
	unsigned long wb_idx = mapping->writeback_index;
	
	/* the host that owns the page.
	if address_space is associated with a swapper, the host field is NULL. */
	struct inode * host = mapping->host;

	struct mm_struct *pt_mm = page->pt_mm;
	struct vm_area_struct *mmap = page->pt_mm->mmap;
	unsigned long vm_start = mmap->vm_start;

	struct writer_t writer = {};
	writer.pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&writer.comm, sizeof(writer.comm));
	page_to_writer_info.update(&vm_start, &writer);
		
	if (host != NULL){
		//data.wb_idx = wb_idx;
		data.vm_start = vm_start;
		bpf_probe_read_str(data.comm, sizeof(data.comm), writer.comm);
		events.perf_submit(ctx, &data, sizeof(data));
	}
	
	return 0;
}

void trace_submit_bio(struct pt_regs *ctx, struct bio *bio) 
{
	struct data_t data = {};
	
	struct bio_vec *bi_io_vec = bio->bi_io_vec;
	struct page *bv_page = bi_io_vec->bv_page;
	unsigned short bi_max_vecs = bio->bi_vcnt;
	int bi_cnt_counter = bio->__bi_cnt.counter; 
	
	//unsigned long vm_start = bv_page->pt_mm->mmap->vm_start;
	
	//struct writer_t *writer = page_to_writer_info.lookup(&vm_start);

	//data.bi_max_vecs = bi_max_vecs;
	//data.bi_cnt = bi_cnt_counter; // usage counter
	

	//data.vm_start = vm_start;
	//bpf_probe_read_str(data.comm, sizeof(data.comm), writer->comm);
	//data.comm = writer->comm;
	//data.pid = writer->pid;
	//events.perf_submit(ctx, &data, sizeof(data));
	return ;
}
