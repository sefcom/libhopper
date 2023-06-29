#!/bin/bash

echo "[*] Building binaries for testing..."
make

gdb ./test -ex 'source ../gdbscript.py' -ex 'q'

make compare
