#!/usr/bin/python

from __future__ import print_function
import atexit
from bcc import BPF

# load BPF program
b= BPF(src_file="bio_trace.c")


b.attach_kprobe(event="submit_bio",fn_name="submit_bio_entry")
b.attach_kprobe(event="blk_init_request_from_bio",fn_name="blk_init_request_from_bio_entry")
b.attach_kprobe(event="bio_endio",fn_name="bio_endio_entry")

trace_file = open('./trace.log','w')

def print_event(cpu,data,size):
	event= b["events"].event(data)
	bio=event.bio
	time=event.time
	request = event.request
	s_size =event.data_size_start;
	e_size =event.data_size_end;
	PID1 = event.PID1;
	PID2 = event.PID2;

	trace_line = ("%u,%lx,%lu,%lu,%lu,%u,%lx\n" % (PID1,bio,time,s_size,e_size,PID2,request))
	trace_file.write(trace_line)

b["events"].open_perf_buffer(print_event)
while 1:
	try :
		b.perf_buffer_poll()
	except KeyboardInterrupt:
                trace_file.close()
                exit()


