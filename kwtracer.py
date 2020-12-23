#!/usr/bin/python

from __future__ import print_function
import atexit
from bcc import BPF
import os
from datetime import datetime

# load BPF program
b= BPF(src_file="kwtracer.c")

b.attach_kprobe(event="iov_iter_copy_from_user_atomic",fn_name="trace_do_user_space_write")
b.attach_kprobe(event="submit_bio", fn_name="trace_submit_bio")

date = datetime.today().strftime("%Y-%m-%d.%H:%M:%S")  
old_trace = "./old_trace/tracelog_" + date + ".log"
print(old_trace)

os.system("sudo cp ./trace.log " + old_trace)

trace_file = open('./trace.log', 'w')

def print_event(cpu,data,size):
        event = b["events"].event(data)
        trace_line = "%s,%s\n" % (event.pid, event.comm)
        trace_file.write(trace_line)

b["events"].open_perf_buffer(print_event)
while 1:
	try :
		b.perf_buffer_poll()
	except KeyboardInterrupt:
                trace_file.close()
                exit()
