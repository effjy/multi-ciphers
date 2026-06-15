# Multi Ciphers - no external dependencies, just a C compiler + libc.
CC      ?= cc
CFLAGS  ?= -O2 -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wshadow
LDFLAGS ?=

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
BIN := multiciphers

# Installation paths (override e.g. with `make install PREFIX=$HOME/.local`)
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
INSTALL ?= install

.PHONY: all clean test install uninstall

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(BIN)
	./$(BIN) selftest

install: $(BIN)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	@echo "Installed $(BIN) to $(DESTDIR)$(BINDIR)/$(BIN)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	@echo "Removed $(DESTDIR)$(BINDIR)/$(BIN)"

clean:
	rm -f $(OBJ) $(BIN)
