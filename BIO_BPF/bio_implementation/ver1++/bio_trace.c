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


// map for struct blk_layer_called_info
// key is address of struct bio, key_size is sizeof(long) == u64
// value is struct blk_layer_called_info, value_size is sizeof(struct bio_called_info)
// max_entriex need to be verified @@@@
BPF_HASH(blk_layer_called_info_map, u64 , struct blk_layer_called_info);

// For recode start time of blk layer to blk_layer_called_info
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
/*
void dio_bio_complete_entry(struct pt_regs *ctx,void * dio , struct bio* bio){
	u64 ptr_bio = (u64)bio;
	struct blk_layer_called_info* blk_layer_called_info;
	u64 end_time = bpf_ktime_get_ns();

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	u64 sector = bio->bi_iter.bi_sector;
	u64 size = bio->bi_iter.bi_size;
	blk_layer_called_info = blk_layer_called_info_map.lookup( &ptr_bio);
	if(!blk_layer_called_info){
		bpf_trace_printk("biodiocom : not in map 0x%lx\n",ptr_bio);
		bpf_trace_printk("      comm : %s\n",comm);
		bpf_trace_printk("      sector no : %llu\n",sector);
		bpf_trace_printk("      size : %llu\n",size);
		bpf_trace_printk("      time : %llu\n",end_time);
		return;
	}

		
	bpf_trace_printk("biodio : finish 0x%lx\n" ,ptr_bio);
	bpf_trace_printk("      comm : %s\n",comm);
	bpf_trace_printk("      sector no : %llu\n",sector);
	bpf_trace_printk("      size : %llu\n",size);
	bpf_trace_printk("      time : %llu\n",end_time);


        return ;


}


// For recode end time of blk layer to blk_layer_called_info
void bio_endio_entry(struct pt_regs *ctx, struct bio* bio){
//void dio_complete_entry(struct pt_regs *ctx, struct dio * dio){

	u64 ptr_bio = (u64)bio;
	u64 ptr_request;
	u64 start_time = 0;
        u64 end_time = bpf_ktime_get_ns();

        struct blk_layer_called_info* blk_layer_called_info;

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	u64 sector = bio->bi_iter.bi_sector;
	u64 size = bio->bi_iter.bi_size;
        blk_layer_called_info = blk_layer_called_info_map.lookup( &ptr_bio);
        if(!blk_layer_called_info){
                bpf_trace_printk("endio : not in map 0x%lx\n",ptr_bio);
		bpf_trace_printk("      comm : %s\n",comm);
		bpf_trace_printk("      sector no : %llu\n",sector);
		bpf_trace_printk("      size : %llu\n",size);
		bpf_trace_printk("      time : %llu\n",end_time);
		return;
        }


		
	bpf_trace_printk("endio : finish 0x%lx\n" ,ptr_bio);
	bpf_trace_printk("      comm : %s\n",comm);
	bpf_trace_printk("      sector no : %llu\n",sector);
	bpf_trace_printk("      size : %llu\n",size);
	bpf_trace_printk("      time : %llu\n",end_time);


        return ;

}
*/
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

