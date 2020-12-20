#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"


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
struct bpf_map_def SEC("maps") bio_to_request_info_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(long),
	.value_size = sizeof(struct bio_to_request_info),
	.max_entries = 4096,
};

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
struct bpf_map_def SEC("maps") blk_layer_called_info_map ={
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(long),
	.value_size = sizeof(struct blk_layer_called_info),
	.max_entries = 4096,
};


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
struct bpf_map_def SEC("maps") nvme_layer_called_info_map ={
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(long),
	.value_size = sizeof(struct nvme_layer_called_info),
	.max_entries = 4096,
};


// For recode start time of blk layer to blk_layer_called_info
SEC("kprobe/submit_bio")
int submit_bio_entry(struct pt_regs *ctx){

	char fmt[] = "submit_bio(bio=0x%lx) called: %llu\n";
	u64 start_time = bpf_ktime_get_ns();
	long ptr_bio = PT_REGS_PARM1(ctx);
	struct blk_layer_called_info blk_layer_called_info = {
		.start = start_time,
		.end = 0
	};

	bpf_map_update_elem(&blk_layer_called_info_map, &ptr_bio, &blk_layer_called_info, BPF_ANY);
	bpf_trace_printk(fmt, sizeof(fmt), ptr_bio, start_time);
	return 0;
}

// For connecting struct request and struct bio
//SEC("kprobe/blk_mq_bio_to_request")
SEC("kprobe/blk_init_request_from_bio")
int blk_init_request_from_bio_entry(struct pt_regs *ctx){
	
	char fmt[] = "Connect (bio=0x%lx) and (request=0x%lx)\n";
	char er[] = "This bio is not registered\n";
	long ptr_bio = PT_REGS_PARM2(ctx);
	long ptr_request = PT_REGS_PARM1(ctx);
	
	struct blk_layer_called_info* blk_layer_called_info;

	blk_layer_called_info = bpf_map_lookup_elem(&blk_layer_called_info_map, &ptr_bio);
	if( !blk_layer_called_info){
		bpf_trace_printk(er,sizeof(er));
		return 0;
	}

	struct bio_to_request_info bio_to_request_info= {
		.bio_addr = ptr_bio,
		.request_addr = ptr_request
	};

	bpf_map_update_elem(&bio_to_request_info_map, &ptr_bio, &bio_to_request_info, BPF_ANY);
	bpf_trace_printk(fmt,sizeof(fmt), ptr_bio, ptr_request);
	
	return 0;
}

//For recode start time of nvme layer to nvme_layer_called_info


// For recode end time of blk layer to blk_layer_called_info
SEC("kprobe/bio_endio")
int bio_endio_entry(struct pt_regs *ctx){

	char fmt[] = "bio_endio (bio=0x%lx) called: %llu\n";
	char fmt2[] = "struct bio(0x%lx) is connected with struct request(0x%lx)\n";

	char er[] = "This bio is not registered at blk_layer_called_info_map\n";
	char er2[] = "This bio is not connected with request\n";

	u64 end_time = bpf_ktime_get_ns();
	long ptr_bio = PT_REGS_PARM1(ctx);

	struct blk_layer_called_info* blk_layer_called_info;
	struct bio_to_request_info* bio_to_request_info;

	blk_layer_called_info = bpf_map_lookup_elem(&blk_layer_called_info_map, &ptr_bio);
	if(!blk_layer_called_info){
		bpf_trace_printk(er,sizeof(er));
		return 0;
	}

	blk_layer_called_info->end = end_time;


	
	bio_to_request_info = bpf_map_lookup_elem(&bio_to_request_info_map, &ptr_bio);
	if(!bio_to_request_info){
		bpf_trace_printk(er2,sizeof(er2));
		return 0;
	}

	long ptr_request = bio_to_request_info->request_addr;
	bpf_trace_printk(fmt2,sizeof(fmt2),ptr_bio,ptr_request);

	return 0;

}



char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
























