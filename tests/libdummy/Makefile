# # Partially referenced: https://stackoverflow.com/a/31421842
# CC              =       gcc
# CFLAGS          +=      -Wall -g -c


# .PHONY : all clean runtest

# all: test

# test: test.o libdummy.a
# 	@$(CC) -lm -o test test.o -L. -ldummy

# test.o: test.c
# 	@$(CC) $(CFLAGS) test.c dummy.h

# dummy.o: dummy.c
# 	@$(CC) $(CFLAGS) dummy.c dummy.h

# libdummy.a: dummy.o
# 	@ar rcs libdummy.a dummy.o

# clean:
# 	@rm -rf test *.o *.a *.gch

# Compiler and linker flags
CC = gcc
CFLAGS = -g -Wall -fpic
LDFLAGS = -shared

# Target files
LIBNAME = libdummy.so
LIBDIR = $(HOME)/.local/lib
SRCS = dummy.c
OBJS = $(SRCS:.c=.o)
TESTFILE = test.c

# Default target
all: $(LIBNAME) test

# Build the shared library
$(LIBNAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(LIBNAME) $(OBJS)
	install -d $(LIBDIR)
	install $(LIBNAME) $(LIBDIR)

# Build the test executable
test: $(TESTFILE) $(LIBNAME)
	$(CC) $(CFLAGS) -o test $(TESTFILE) -L$(LIBDIR) -ldummy

# Compile the source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJS) $(LIBNAME) test
	rm -rf $(LIBDIR)/$(LIBNAME)

.PHONY: all clean