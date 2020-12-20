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
	u64 size;
        u64 end;
};

// Map for recoding start time and end time of block layer.
// Block layer is assumed start at blk_mq_make_request and end at bio_put.
// Key is end sector address of each bio.
// Value is struct blk_layer_called_info.
BPF_HASH(blk_layer_called_info_map, u64 , struct blk_layer_called_info);

// key will be bio_addr when connect bio to nvme
struct bio_to_request_info{
	struct request * request_addr;
};

BPF_HASH(bio_to_request_info_map, u64, struct bio_to_request_info);

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
		.size = size,
                .end = 0
        };

	struct blk_layer_called_info * already;
	already = blk_layer_called_info_map.lookup(&key);

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	u64 major = bio->bi_disk->major;

	if( !already){
		blk_layer_called_info_map.update( &key, &blk_layer_called_info);
		bpf_trace_printk("blk_mq_make, map ,%lu, major, %lu\n",key, major);
	}
	else{
		bpf_trace_printk("blk_mq_make, already registered sector , %lu, major, %lu\n",key,major);
	}

        return ;
}

void blk_init_request_from_bio_entry(struct pt_regs *ctx, struct request * rq, struct bio * bio){

	u64 sector = bio->bi_iter.bi_sector;
	u64 size = bio->bi_iter.bi_size;
	u64 key = sector + size / 512;

	u64 major = bio->bi_disk->major;
	
	struct blk_layer_called_info* blk_layer_called_info;
	blk_layer_called_info =blk_layer_called_info_map.lookup(&key);
	if( !blk_layer_called_info ){
		bpf_trace_printk("blk_init, bio is not mapped, %lu, major, %lu\n",key,major);
		return;
	}	
	struct bio_to_request_info bio_to_request_info = {
		.request_addr = rq
	};
	
	struct bio_to_request_info * already;
	already = bio_to_request_info_map.lookup(&key);	
		
	if( !already){
		bio_to_request_info_map.update( &key, &bio_to_request_info);
		bpf_trace_printk("blk_init, map, %lu, major, %lu, request, %lu\n",key,major,rq);
	}
	else{ 
		bpf_trace_printk("blk_init, already request, %lu, major, %lu\n",key,major);
	}
	return;

}

void bio_attempt_back_merge_entry(struct pt_regs *ctx, struct request_queue *q, struct request *rq,
				struct bio *bio){
	u64 sector = bio->bi_iter.bi_sector;
	u64 size = bio->bi_iter.bi_size;
	u64 key = sector + size / 512;
	
	struct blk_layer_called_info* blk_layer_called_info;
	u64 major = bio->bi_disk->major;

	blk_layer_called_info = blk_layer_called_info_map.lookup( &key);
	if(!blk_layer_called_info){
	        bpf_trace_printk("back merge, bio not in map, %lu, major, %lu\n",key,major);
		return;
        }
	struct bio_to_request_info bio_to_request_info = {
		.request_addr = rq
	};
	
	struct bio_to_request_info * already;
	already = bio_to_request_info_map.lookup(&key);	
		
	if( !already){
		bio_to_request_info_map.update( &key, &bio_to_request_info);
		bpf_trace_printk("back merge, map, %lu, major, %lu, request, %lu\n",key,major,rq);
	}
	else{ 
		bpf_trace_printk("back merge, already request, %lu, major, %lu\n",key,major);
	}
	return;



}

void bio_attempt_front_merge_entry(struct pt_regs *ctx, struct request_queue *q, struct request *rq,
				struct bio *bio){
	u64 sector = bio->bi_iter.bi_sector;
	u64 size = bio->bi_iter.bi_size;
	u64 key = sector + size / 512;
	
	struct blk_layer_called_info* blk_layer_called_info;
	u64 major = bio->bi_disk->major;

	blk_layer_called_info = blk_layer_called_info_map.lookup( &key);
	if(!blk_layer_called_info){
	        bpf_trace_printk("back merge, bio not in map, %lu, major, %lu\n",key,major);
		return;
        }
	struct bio_to_request_info bio_to_request_info = {
		.request_addr = rq
	};
	
	struct bio_to_request_info * already;
	already = bio_to_request_info_map.lookup(&key);	
		
	if( !already){
		bio_to_request_info_map.update( &key, &bio_to_request_info);
		bpf_trace_printk("back merge, map, %lu, major, %lu, request, %lu\n",key,major,rq);
	}
	else{ 
		bpf_trace_printk("back merge, already request, %lu, major, %lu\n",key,major);
	}
	return;



}

void bio_attempt_discard_merge_entry(struct pt_regs *ctx, struct request_queue *q, struct request *rq,
				struct bio *bio){
	u64 sector = bio->bi_iter.bi_sector;
	u64 size = bio->bi_iter.bi_size;
	u64 key = sector + size / 512;
		
	struct blk_layer_called_info* blk_layer_called_info;
	u64 major = bio->bi_disk->major;

	blk_layer_called_info = blk_layer_called_info_map.lookup( &key);
	if(!blk_layer_called_info){
	        bpf_trace_printk("back merge, bio not in map, %lu, major, %lu\n",key,major);
		return;
        }
	struct bio_to_request_info bio_to_request_info = {
		.request_addr = rq
	};
	
	struct bio_to_request_info * already;
	already = bio_to_request_info_map.lookup(&key);	
		
	if( !already){
		bio_to_request_info_map.update( &key, &bio_to_request_info);
		bpf_trace_printk("back merge, map, %lu, major, %lu, request, %lu\n",key,major,rq);
	}
	else{ 
		bpf_trace_printk("back merge, already request, %lu, major, %lu\n",key,major);
	}
	return;



}

// For recoding end time of blk layer to blk_layer_called_info.
// Key is also address of sercotr in bio.
// It can be accessed by bio->bi_iter.bi_sector.
// Value is also struct blk_layer_called_info.
void bio_endio_entry(struct pt_regs *ctx, struct bio* bio){

	u64 sector = bio->bi_iter.bi_sector;
	u64 key = sector;

	struct blk_layer_called_info* blk_layer_called_info;
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));
	u64 end_time = bpf_ktime_get_ns();
	
	u64 major = bio->bi_disk->major;

	u64 size = bio->bi_iter.bi_size;
	blk_layer_called_info = blk_layer_called_info_map.lookup( &key);
        if(!blk_layer_called_info){
                bpf_trace_printk("bio_endio, not in map, %lu, major, %lu\n",key,major);
		return;
        }
	
	struct bio_to_request_info * bio_to_request_info;
	bio_to_request_info = bio_to_request_info_map.lookup(&key);
	if(!bio_to_request_info){
		bpf_trace_printk("bio_endio, rq not map, %lu, major, %lu\n",key,major);
		blk_layer_called_info_map.delete(&key);
		return;	
	}
	u64 psize = blk_layer_called_info->size;
	blk_layer_called_info_map.delete(&key);
	bio_to_request_info_map.delete(&key);
	bpf_trace_printk("bio_endio, delete, %lu, major, %lu, size, %u\n", key, major, psize);
	return;
}

/*

void blk_mq_end_request_entry(struct pt_regs *ctx, struct request * rq, blk_status_t error ){


	struct bio * bio = rq->bio;
	struct bio * biotail = rq->biotail;
	u64 key;
	u64 sector;
	u64 size;
	struct blk_layer_called_info* blk_layer_called_info;
	u64 major;
	
	while(bio){
		sector = bio->bi_iter.bi_sector;
		key = sector;
		major = bio->bi_disk->major;
		blk_layer_called_info = blk_layer_called_info_map.lookup( &key);
		if(!blk_layer_called_info){
			bpf_trace_printk("request end, not in map, %lu, major, %lu\n",key,major);
		}
		else{
			size = blk_layer_called_info->size;	
			bpf_trace_printk("request end, map, %lu, major, %lu, size, %lu\n",key,major,size);
		}
		bio = bio->bi_next;
	}


	return;
}


 */
