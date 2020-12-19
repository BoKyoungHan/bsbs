#!/usr/bin/python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created this.
from __future__ import print_function
import atexit
from bcc import BPF
from bcc.utils import printb

REQ_OP_READ = 0
REQ_OP_WRITE = 1
REQ_OP_DISCARD = 3
REQ_OP_WRITE_ZEROS = 9

SECTOR_SIZE = 512

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>

#pragma pack(4)
struct data_t {
    u64 submit_ts;
    u64 sector;
    u64 data_len;
    u32 cmd_flags;
    u32 dev_num;
};
BPF_PERF_OUTPUT(events);

void trace_start(struct pt_regs *ctx, struct request *req) {

        struct data_t data = {};

        data.submit_ts =  bpf_ktime_get_ns();
        data.dev_num = 1;
        data.sector = req->__sector;
        data.data_len = req->__data_len;
        data.cmd_flags = req->cmd_flags;

        events.perf_submit(ctx, &data, sizeof(data));

}
""")

b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")


trace_file = open ('./kwtrace/trace.log', 'w')

def print_event(cpu, data, size):
    event = b["events"].event(data)
    req_op = ((event.cmd_flags) & ((1 << 8) -1))
    data_len = event.data_len/SECTOR_SIZE

    if req_op == REQ_OP_WRITE:
        type_of_req = 0
        trace_line = ('%s %s %s %s %s\n' % (event.submit_ts, event.dev_num, event.sector, data_len, type_of_req))
        trace_file.write(trace_line)
        print("%s %s %s %s %s" % (event.submit_ts, event.dev_num, event.sector, data_len, type_of_req))
    elif req_op == REQ_OP_READ:
        type_of_req = 1
        trace_line = ('%s %s %s %s %s\n' % (event.submit_ts, event.dev_num, event.sector, data_len, type_of_req))
        trace_file.write(trace_line)
        print("%s %s %s %s %s" % (event.submit_ts, event.dev_num, event.sector, data_len, type_of_req))
    elif req_op == REQ_OP_DISCARD:
        type_of_req = 2
        trace_line = ('%s %s %s %s %s\n' % (event.submit_ts, event.dev_num, event.sector, data_len, type_of_req))
        trace_file.write(trace_line)
        print("%s %s %s %s %s" % (event.submit_ts, event.dev_num, event.sector, data_len, type_of_req))


b["events"].open_perf_buffer(print_event)
while 1:
	try:
                b.perf_buffer_poll()
	except KeyboardInterrupt:
                trace_file.close()
                exit()

