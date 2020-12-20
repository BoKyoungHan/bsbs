#!/bin/bash

NOW=`date '+%Y.%m.%d-%H.%M'`

NVDISK_DIR="/home/bkhan/kworker_tracer/old_trace"

if [ -d "$NVDISK_DIR" ]; then
    echo "$NVDISK_DIR already mounted"
else
    echo "Make $NVDISK_DIR DIR"
    mkdir $NVDISK_DIR
fi

sudo cp -r /home/bkhan/kworker_tracer/kwtrace/trace.log $NVDISK_DIR/tracelog_$NOW.log &
wait

echo "[GENERATING TRACE FILE FOR MQSIM COMPLETE]"
echo "TRACE FILE in RAMDISK is copied to old_mqtrace dir in your home directory"

sudo rm /home/bkhan/kworker_tracer/kwtrace/trace.log
wait
sudo umount /home/bkhan/kworker_tracer/kwtrace

echo "	UNMOUNT ./kwtrace DONE"

