# Partially referenced: https://stackoverflow.com/a/31421842
CC              =       gcc
CFLAGS          +=      -Wall -g -c


.PHONY : all clean runtest compare

all: test

test: test.o libfakelib.a
	@$(CC) -lm -o test test.o -L. -lfakelib

test.o: test.c
	@$(CC) $(CFLAGS) test.c fakelib.h

fakelib.o: fakelib.c
	@$(CC) $(CFLAGS) fakelib.c fakelib.h

libfakelib.a: fakelib.o
	@ar rcs libfakelib.a fakelib.o

clean:
	@rm -rf test *.o *.a *.gch

runtest:
	@echo "Follow the command below:"
	@echo "$$ cp ../gdbscript.py ./"
	@echo "$$ gdb ./test"
	@echo "(gdb) source ./gdbscript.py"

compare: all
	@cmp Crash_Funcs.txt expected.txt