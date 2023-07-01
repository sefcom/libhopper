#!/bin/bash

# File to be split
input_file="Todo_Funcs.txt"

# Number of desired output files
num_files=8

# Calculate the total line count of the input file
total_lines=$(wc -l < "$input_file")

# Calculate the number of lines per output file
lines_per_file=$((total_lines / num_files - 1))

# Split the file using 'split' command
split -l "$lines_per_file" "$input_file" tmp

# Rename the output files with a prefix
prefix="Todos"
counter=1

for file in tmp*
do
  mkdir "$prefix$counter"
  mv "$file" "$prefix$counter/Todo_Funcs.txt"
  cp "config.ini" "$prefix$counter/"
  touch "$prefix$counter/Finish_Funcs.txt"
  counter=$((counter + 1))
done

rm -rf tmp*