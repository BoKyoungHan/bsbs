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


trace_file = open('./trace.csv','w')

def print_event(cpu,data,size):
	event= b["events"].event(data)
	fun=event.fun
	key=event.key
	state=event.state
	major=event.major
	minor=event.minor
	sector_no=event.sector_no
	sector_size=event.sector_size
	sector_done=event.sector_done
	time=event.time
	comm= event.comm

	trace_line = ("%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%s\n" % (fun,key,state,major,minor,sector_no,sector_size,sector_done,time,comm))
	trace_file.write(trace_line)

b["events"].open_perf_buffer(print_event)
while 1:
	try :
		b.perf_buffer_poll()
	except KeyboardInterrupt:
                trace_file.close()
                exit()


