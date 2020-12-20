#!/usr/bin/python

from __future__ import print_function
import atexit
from bcc import BPF

# load BPF program
b= BPF(src_file="bio_trace.c")


#b.attach_kprobe(event="submit_bio",fn_name="submit_bio_entry")
#b.attach_kprobe(event="dio_bio_complete",fn_name="dio_bio_complete_entry")
#b.attach_kprobe(event="bio_endio",fn_name="bio_endio_entry")
b.attach_kprobe(event="blk_mq_make_request", fn_name="blk_mq_make_request_entry")
b.attach_kprobe(event="bio_put",fn_name="bio_put_entry")


trace_file = open('./trace.log','w')

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


