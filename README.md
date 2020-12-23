## Advanced Operating Systems (Fall 2020)
---
### Final Project
Development of kworker Thread Monitoring Tool for Improving Multi-core Proesssing Performance

### Kernel version
5.4.59

### Install build dependencies
* bcc

### How to run
$ sudo python kwtracer.py

### File descriptions
* **kwtracer.py**: BPF tracing tool to monitor 2 tracing point.
* **count.py**: Recdives the _trace.log_ file as an input and outputs the _counted_trace.csv_ file. 
