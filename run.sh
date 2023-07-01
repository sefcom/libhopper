#!/bin/bash

test_path=./test

gdb "$test_path" -ex 'source ./gdbsetup.py'

bash ./split.sh

for dir in Todos*
do
    # (cd $dir && gdb "../$test_path" -ex 'source ../gdbcorruption.py' > /dev/null 2>&1 &)
    (cd $dir && gdb "../$test_path" -ex 'source ../gdbcorruption.py' &)
done