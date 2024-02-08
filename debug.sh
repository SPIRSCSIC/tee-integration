#!/bin/bash

# The project must be compiled with -DCMAKE_BUILD_TYPE=Debug
# Start the qemu with "make -j debug"

[ $# -ne 1 ] && echo "Usage: $0 <DEBUG-PORT>" && exit

command -V gdb-multiarch > /dev/null 2>&1
[ $? -eq 0 ] || { apt update && apt install -y gdb-multiarch; }

gdb-multiarch \
    -ex "target remote localhost:$1" \
    -ex "set confirm off" \
    -ex "add-symbol-file build/pkg/4a4f7741-cb9f-4cfc-914f-81beb2060a66.ta" \
    $KEYSTONE_BUILD_DIR/buildroot.build/build/linux-5.19/vmlinux
