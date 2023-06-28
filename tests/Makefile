# Partially referenced: https://stackoverflow.com/a/31421842
CC              =       gcc
CFLAGS          +=      -Wall -g -c


.PHONY : all clean compare

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
	@rm -rf Crash_Funcs.txt Finish_Funcs.txt Todo_Funcs.txt
	@rm -rf gdbscript.py

compare: all
	@diff Crash_Funcs.txt expected.txt