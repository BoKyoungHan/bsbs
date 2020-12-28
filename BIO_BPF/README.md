# IOPro_js


##bio_implementation
###ver1
start of makeing trace program
c version
###ver1+
bcc version
###ver1++
change submit_bio to blk_mq_make_request
change bio_endio to bio_put
###ver2
change key address to sector
###ver3_bioaddr
using key as bio address
change bio_put to bio_endio
###ver3_sector
using key as bio sector address
change bio_put to bioe_endio

##bio_to_nvme
###ver1
map bio and request at blk_init_requset
check mapping is done well at bio_endio 


=======
Experiment

## Tracing output
sudo su
cd /sys/kernel/debug/tracing
echo > trace
cat trace_pipe
// with ramdisk
cat trace_pipe > /mqtrace/output.txt

## Run tracer
sudo python tracer.py

## Set Ramdisk
cd ~/ramdisk
sudo sh ./load.sh

//unload
sudo sh ./unload.sh

