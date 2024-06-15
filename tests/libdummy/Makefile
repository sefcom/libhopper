# Compiler and linker flags
CC = gcc
CFLAGS = -g -Wall -fpic
LDFLAGS = -shared

# Target files
LIBNAME = libdummy.so
SRCS = dummy.c
OBJS = $(SRCS:.c=.o)
TESTFILE = test.c

# Default target
all: $(LIBNAME) test

# Build the shared library
$(LIBNAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(LIBNAME) $(OBJS)

# Compile the source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build the test executable
test: $(TESTFILE) $(LIBNAME)
	$(CC) $(CFLAGS) -o test $(TESTFILE) -L. -ldummy

# Run the test
runtest: test
	LD_LIBRARY_PATH=. ./test

# Clean up
clean:
	rm -f $(OBJS) $(LIBNAME) test

.PHONY: all clean
