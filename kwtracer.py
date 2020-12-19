#!/usr/bin/python

from __future__ import print_function
import atexit
from bcc import BPF
import os

# load BPF program
b= BPF(src_file="kwtracer.c")

b.attach_kprobe(event="blk_mq_start_request",fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_completion",fn_name="trace_req_completion")
#b.attach_kprobe(event="iov_iter_copy_from_user_atomic",fn_name="trace_do_user_space_write")
#b.attach_kprobe(event="ntfs_copy_from_user_iter",fn_name="trace_do_user_space_write")
b.attach_kprobe(event="submit_bio", fn_name="trace_submit_bio")

# header
header = "%-26s %-10s %-10s %-24s %-10s %-16s %-16s %-1s" % ("TS", "PPID", "PID", "COMM", "DISK", "SECTOR", "LEN", "T")
rwflag = ""
trace_file = open('./diskIO_trace.log', 'w')
#trace_file.write(header)
print(header)

def print_event(cpu,data,size):
        event = b["events"].event(data)

        if event.rwflag == 1:
            rwflag = "W"
        else:
            rwflag = "R"

        length = event.len >> 9
        if event.disk_name != "":
            trace_line = "%-26s %-10s %-10s %-24s %-10s %-16s %-16s %-1s" % (event.ts, event.ppid, event.pid, event.comm, event.disk_name, event.sector, length, rwflag)
            #trace_file.write(trace_line)
            print(trace_line)

b["events"].open_perf_buffer(print_event)
while 1:
	try :
		b.perf_buffer_poll()
	except KeyboardInterrupt:
                trace_file.close()
                exit()



