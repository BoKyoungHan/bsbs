#!/bin/bash

NOW=`date '+%Y.%m.%d-%H.%M'`

NVDISK_DIR="/home/es2020/kworker_tracer/old_trace"

if [ -d "$NVDISK_DIR" ]; then
    echo "$NVDISK_DIR already mounted"
else
    echo "Make $NVDISK_DIR DIR"
    mkdir $NVDISK_DIR
fi

cp -r /home/es2020/kworker_tracer/kwtrace/trace.log $NVDISK_DIR/tracelog_$NOW.log &
wait

echo "[GENERATING TRACE FILE FOR MQSIM COMPLETE]"
echo "TRACE FILE in RAMDISK is copied to old_mqtrace dir in your home directory"

rm /home/es2020/kworker_tracer/kwtrace/trace.log
wait
sudo umount /home/es2020/kworker_tracer/kwtrace

echo "	UNMOUNT ./kwtrace DONE"

