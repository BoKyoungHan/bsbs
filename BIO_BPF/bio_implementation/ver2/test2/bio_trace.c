#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>

#pragma pack(4)
struct data_t {
	u64 fun;
	u64 key;
	u64 state;
	u64 major;
	u64 minor;
	u64 sector_no;
	u64 sector_size;
	u64 sector_done;
	u64 time;
	char comm[TASK_COMM_LEN];	
};
BPF_PERF_OUTPUT(events);
// fun, 0 = make requet, 1 = put_bio
//state, 3 = normal, 4 = already, 5 = not

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
	u64 bio_done = bio->bi_iter.bi_bvec_done;
	u64 major = bio->bi_disk->major;
	u64 minor = bio->bi_disk->minors;
	
	u64 start_time = bpf_ktime_get_ns();
		

        struct blk_layer_called_info blk_layer_called_info = {
                .start = start_time,
                .end = 0
        };

	struct blk_layer_called_info * already;
	already = blk_layer_called_info_map.lookup(&key);

	char comm[TASK_COMM_LEN];
	//bpf_get_current_comm(&comm, sizeof(comm));

	struct data_t data = {};	
	data.fun = 0;
	data.key = key;
	if( !already){
		data.state = 3;
		blk_layer_called_info_map.update( &key, &blk_layer_called_info);
	}
	else{
		data.state =4 ;
	}
	data.major = major;
	data.minor = minor;
	data.sector_no = sector;
	data.sector_size = size;
	data.sector_done = bio_done;
	data.time = start_time;
	//strcpy(data.comm, comm);
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	events.perf_submit(ctx,&data,sizeof(data));

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
	//bpf_get_current_comm(&comm, sizeof(comm));
	u64 end_time = bpf_ktime_get_ns();
	
	u64 size = bio->bi_iter.bi_size;
	u64 bio_done = bio->bi_iter.bi_bvec_done;
	blk_layer_called_info = blk_layer_called_info_map.lookup( &key);
	u64 major = bio->bi_disk->major;
	u64 minor = bio->bi_disk->minors;
	
	struct data_t data = {};	
	data.fun = 1;
	data.key = key;

        if(!blk_layer_called_info){
        	data.state = 5;
	}
	else{
		data.state = 0;
		blk_layer_called_info_map.delete(&key);
	}
	data.major = major;
	data.minor = minor;
	data.sector_no = sector;
	data.sector_size = size;
	data.sector_done = bio_done;
	data.time = end_time;
	//strcpy(data.comm, comm);
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	events.perf_submit(ctx,&data,sizeof(data));



	return;
}

