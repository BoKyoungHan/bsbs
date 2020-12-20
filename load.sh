#!/bin/bash

RAMDISK_DIR="/home/bkhan/kworker_tracer/kwtrace"

'''if [ -d "$RAMDISK_DIR" ]; then
    echo "[INFO] $RAMDISK_DIR already mounted"
else''' 
    echo "[INFO] Mounting $RAMDISK_DIR for logging [1G]"
    mkdir $RAMDISK_DIR
    sudo mount tmpfs $RAMDISK_DIR -t tmpfs -o size=1G &
    wait
#fi

rm $RAMDISK_DIR/trace.log

