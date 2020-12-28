#!/usr/bin/python

from __future__ import print_function
import atexit
from bcc import BPF
from bcc.utils import printb
import sys


# load BPF program
b= BPF(src_file="bio_trace.c")


b.attach_kprobe(event="blk_mq_make_request", fn_name="blk_mq_make_request_entry")
b.attach_kprobe(event="bio_put",fn_name="bio_put_entry")


trace_file = open('./trace.log','w')

def print_event(cpu,data,size):
	event= b["events"].event(data)
	done = event.done
	trace_line = (" %lu \n" % (done))
	trace_file.write(trace_line)

b["events"].open_perf_buffer(print_event)
while 1:
	try :
		b.perf_buffer_poll()
	except KeyboardInterrupt:
                trace_file.close()
                exit()


