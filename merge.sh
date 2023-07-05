#!/bin/bash

echo "Func Name - Param Name - Corrupt Type - If Bit Flip - Corrupt Range" >> ./Crash_Funcs.txt

for dir in Todos*
do
    cat "$dir/Crash_Funcs.txt" >> ./Merge.txt
done

sort ./Merge.txt >> ./Crash_Funcs.txt
rm ./Merge.txt