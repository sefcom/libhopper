#!/bin/bash

echo "[*] Link script to working dir..."
ln -s ../gdbscript.py ./gdbscript.py

echo "[*] Building binaries for testing..."
make

gdb ./test -ex 'source gdbscript.py' -ex 'q'

echo ""
echo "If you see: [Inferior 1 (process XXX) exited normally]"
echo "This means the script exit correctly"
echo "Ignore the python script exceptions"
echo ""

make compare
