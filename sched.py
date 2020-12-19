#!/usr/bin/python

from __future__ import print_function
import atexit
from bcc import BPF
import os

# load BPF program
b= BPF(src_file="cpu.c")

b.attach_kprobe(event="io_schedule",fn_name="startio_entry")
b.attach_kretprobe(event="io_schedule",fn_name="endio_entry")

#header
header = "%-16s %-6s %-16s" % ("COMM", "PID", "TIME(ns)\n")

trace_file = open('./cpu_trace.log', 'w')
trace_file.write(header)

def print_event(cpu,data,size):
	event = b["events"].event(data)
        trace_line = "%-16s %-6s %-16s\n" % (event.comm, event.pid, event.time)
        trace_file.write(trace_line)
        #print("%-16s %-6s %-16s" % (event.comm, event.pid, event.time))

b["events"].open_perf_buffer(print_event)
while 1:
	try :
		b.perf_buffer_poll()
	except KeyboardInterrupt:
                trace_file.close()
                exit()



