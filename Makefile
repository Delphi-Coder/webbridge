# Makefile for the simple_http_server project

# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = 

# Target executable name
TARGET = webbridge

# Source files
SRCS = webbridge.c
OBJS = $(SRCS:.c=.o)

# Installation directories
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

.PHONY: all clean install uninstall

# Default target to build the program
all: $(TARGET)

# Link the target executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up generated files
clean:
	rm -f $(OBJS) $(TARGET)

# Install the executable to the system
install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/

# Uninstall the executable from the system
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
