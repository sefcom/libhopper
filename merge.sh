#!/bin/bash

for dir in Todos*
do
    cat "$dir/Crash_Funcs.txt" >> ./Crash_Funcs.txt
done