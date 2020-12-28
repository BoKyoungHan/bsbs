#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>

#pragma pack(4)
struct data_t {
	u64 bio;
	u64 time;
	//u64 data_len;
	u64 request;
	//u32 cmd_flags;
	
};
BPF_PERF_OUTPUT(events);


// start and end time of block layer
// start time at submit_bio
// end time at bio_endio
// key will be bio_addr
struct blk_layer_called_info{
        u64 start;
        u64 end;
};


// Map for recoding start time and end time of block layer.
// Block layer is assumed start at blk_mq_make_request and end at bio_put.
// Key is end sector address of each bio.
// Value is struct blk_layer_called_info.
BPF_HASH(blk_layer_called_info_map, u64 , struct blk_layer_called_info);

// For recode start time of blk layer to blk_layer_called_info
// Key is end sector address of this bio.
// Start sector addresss can be accessed bio->bi_iter.bi_sector.
// End sector address can be infered,
// 'start sector addr (bio->bi_iter.bi_sector) + size of input (bio->bi_iter.bi_size) / sector size ( typically 512 bytes)'
void blk_mq_make_request_entry(struct pt_regs *ctx, void * evict, struct bio * bio){

        u64 sector = bio->bi_iter.bi_sector;
	u64 size = bio->bi_iter.bi_size;
	u64 key = sector + size / 512;

	u64 start_time = bpf_ktime_get_ns();
		

        struct blk_layer_called_info blk_layer_called_info = {
                .start = start_time,
                .end = 0
        };

	struct blk_layer_called_info * already;
	already = blk_layer_called_info_map.lookup(&key);

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	if( !already){
		bpf_trace_printk("blk_mq_make : new bio %llu\n",key);
		bpf_trace_printk("	comm : %s\n",comm);
		bpf_trace_printk("	sector no : %llu\n",sector);
		bpf_trace_printk("	size : %llu\n",size);
		bpf_trace_printk("      time : %llu\n",start_time);
		blk_layer_called_info_map.update( &key, &blk_layer_called_info);
	}
	else{
		bpf_trace_printk("blk_mq_make : already registered addr %llu\n",key);
		bpf_trace_printk("      comm : %s\n",comm);
		bpf_trace_printk("      sector no : %llu\n",sector);
		bpf_trace_printk("      size : %llu\n",size);
		bpf_trace_printk("      time : %llu\n",start_time);
	}

        return ;
}

// For recoding end time of blk layer to blk_layer_called_info.
// Key is also address of sercotr in bio.
// It can be accessed by bio->bi_iter.bi_sector.
// Value is also struct blk_layer_called_info.
void bio_put_entry(struct pt_regs *ctx, struct bio* bio){

	u64 sector = bio->bi_iter.bi_sector;
	u64 key = sector;

	struct blk_layer_called_info* blk_layer_called_info;
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));
	u64 end_time = bpf_ktime_get_ns();
	
	u64 size = bio->bi_iter.bi_size;
	blk_layer_called_info = blk_layer_called_info_map.lookup( &key);
        if(!blk_layer_called_info){
                bpf_trace_printk("bioput : not in map %llu\n",key);
		bpf_trace_printk("p      comm : %s\n",comm);
		bpf_trace_printk("p      sector no : %llu\n",sector);
		bpf_trace_printk("p      size : %llu\n",size);
		bpf_trace_printk("p      time : %llu\n",end_time);
		return;
        }


		
	blk_layer_called_info_map.delete(&key);
	bpf_trace_printk("bioput : finish %llu\n" ,key);
	bpf_trace_printk("p      comm : %s\n",comm);
	bpf_trace_printk("p      sector no : %llu\n",sector);
	bpf_trace_printk("p      size : %llu\n",size);
	bpf_trace_printk("p      time : %llu\n",end_time);
}

