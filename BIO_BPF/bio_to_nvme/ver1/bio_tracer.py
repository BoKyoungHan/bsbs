#!/usr/bin/python

from __future__ import print_function
import atexit
from bcc import BPF

# load BPF program
b= BPF(src_file="bio_trace.c")


b.attach_kprobe(event="bio_endio",fn_name="bio_endio_entry")
b.attach_kprobe(event="blk_init_request_from_bio",fn_name="blk_init_request_from_bio_entry")
b.attach_kprobe(event="blk_mq_make_request", fn_name="blk_mq_make_request_entry")

#b.attach_kprobe(event="blk_mq_end_request", fn_name="blk_mq_end_request_entry")


trace_file = open('/mqtrace/trace.log','w')

def print_event(cpu,data,size):
	event= b["events"].event(data)
	bio=event.bio
	time=event.time
	request=event.request
	trace_line = ('bio %s, time %s, request %s\n' % (bio,time,request))
	trace_file.write(trace_line)

b["events"].open_perf_buffer(print_event)
while 1:
	try :
		b.perf_buffer_poll()
	except KeyboardInterrupt:
                trace_file.close()
                exit()


