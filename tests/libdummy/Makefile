# Partially referenced: https://stackoverflow.com/a/31421842
CC              =       gcc
CFLAGS          +=      -Wall -g -c


.PHONY : all clean runtest

all: test

test: test.o libdummy.a
	@$(CC) -lm -o test test.o -L. -ldummy

test.o: test.c
	@$(CC) $(CFLAGS) test.c dummy.h

dummy.o: dummy.c
	@$(CC) $(CFLAGS) dummy.c dummy.h

libdummy.a: dummy.o
	@ar rcs libdummy.a dummy.o

clean:
	@rm -rf test *.o *.a *.gch
	@rm -rf Crash_Funcs.txt Finish_Funcs.txt Todo_Funcs.txt
	@rm -rf gdbscript.py

runtest: all
	@gdb ./test -ex 'source ../gdbscript.py' > /dev/null 2>&1
	@diff Crash_Funcs.txt expected.txt
