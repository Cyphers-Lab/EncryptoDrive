#!/bin/bash
export LD_PRELOAD=/lib/x86_64-linux-gnu/libpthread.so.0
export LD_LIBRARY_PATH="./build/src/fs:./build/src/auth:/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu"
exec ./build/bin/encrypto-gui "$@"
