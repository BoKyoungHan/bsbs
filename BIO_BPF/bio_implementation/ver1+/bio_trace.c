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

// key will be bio_addr when connect bio to nvme
// later, may be somting in filesystem
struct bio_to_request_info{
        u64 bio_addr;
        u64 request_addr;
};

// map for struct bio_to_request_info
// key is address of struct bio @@@@, key_size is sizeof(long) == u64
// value is sturct bio_to_request_info. value_size is sizeof(struct bio_to_request_info)
// max_entries need to be verified @@@@
BPF_HASH(bio_to_request_info_map, u64 , struct bio_to_request_info);

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


// start and end time of nvme layer
// start time at nvme_queue_rq
// end time at @@@@
// key will be request addr
struct nvme_layer_called_info{
        u64 start;
        u64 end;
};

// map for struct nvme_layer_called_info
// key is address of sturct request, key_size is sizeof(long) == u64
// value is struct nvme_layer_called_info, value_size is sizeof(struct request_called_info)
// max_entriex need to be verified @@@@
BPF_HASH(nvme_layer_called_info_map, u64, struct nvme_layer_called_info);

// For recode start time of blk layer to blk_layer_called_info
void submit_bio_entry(struct pt_regs *ctx, struct bio * bio){

        u64 start_time = bpf_ktime_get_ns();
	u64 ptr_bio = (u64)bio;
        struct blk_layer_called_info blk_layer_called_info = {
                .start = start_time,
                .end = 0
        };

	u64 major = bio->bi_disk->major;

	struct blk_layer_called_info* blk_layer_called_info2;
	blk_layer_called_info2 = blk_layer_called_info_map.lookup(&ptr_bio);
	if( blk_layer_called_info2){
		bpf_trace_printk("already %u\n",major);
		
		return;
	}
	

        blk_layer_called_info_map.update( &ptr_bio, &blk_layer_called_info);
//        bpf_trace_printk("submit_bio(bio=0x%lx) called: %llu\n", ptr_bio, start_time);
        return ;
}

// For connecting struct request and struct bio
void blk_init_request_from_bio_entry(struct pt_regs *ctx, struct request * req, struct bio * bio){


	u64 ptr_request = (u64)req;
	u64 ptr_bio = (u64)bio;
        struct blk_layer_called_info* blk_layer_called_info;
	
        blk_layer_called_info = blk_layer_called_info_map.lookup(&ptr_bio);
        if( !blk_layer_called_info){
//                bpf_trace_printk("This bio is not registered\n");
                return ;
        }

        struct bio_to_request_info bio_to_request_info= {
                .bio_addr = ptr_bio,
                .request_addr = ptr_request
        };

        bio_to_request_info_map.update( &ptr_bio, &bio_to_request_info);
//        bpf_trace_printk("Connect (bio=0x%lx) and (request=0x%lx)\n" , ptr_bio, ptr_request);

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
        struct bio_to_request_info* bio_to_request_info;

	u64 major = bio->bi_disk->major;

        blk_layer_called_info = blk_layer_called_info_map.lookup( &ptr_bio);
        if(!blk_layer_called_info){
                bpf_trace_printk("Bio is not registered %u\n",major);
                return ;
        }

        blk_layer_called_info->end = end_time;
	start_time = blk_layer_called_info->start;


//        bio_to_request_info = bio_to_request_info_map.lookup(&ptr_bio);
//        if(!bio_to_request_info){
//                bpf_trace_printk("This bio is not connected with request\n");
//                return ;
//        }

        ptr_request = bio_to_request_info->request_addr;

//	bpf_trace_printk("bio_endio (bio=0x%lx) called: %llu\n" ,ptr_bio,end_time);
//        bpf_trace_printk( "struct bio(0x%lx) is connected with struct request(0x%lx)\n",ptr_bio,ptr_request);


	blk_layer_called_info_map.delete(&ptr_bio);	

//	struct data_t data = {};
//	data.bio = ptr_bio;
//	data.time = start_time-end_time;
//	data.request = ptr_request;
//	events.perf_submit(ctx,&data,sizeof(data));

        return ;

}



