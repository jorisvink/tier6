# tier6 Makefile

CC?=cc
OBJDIR?=obj

BIN=tier6

CFLAGS+=-std=c99 -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2 -fPIC
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -g
CFLAGS+=-Iinclude

CFLAGS+=$(shell pkg-config --cflags libkyrka)
LDFLAGS+=$(shell pkg-config --libs libkyrka)

SRC=	src/tier6.c \
	src/config.c \
	src/discovery.c \
	src/peer.c \
	src/tap.c

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
endif

ifeq ("$(COVERAGE)", "1")
	CFLAGS+=-fprofile-arcs -ftest-coverage
endif

ifeq ("$(OSNAME)", "")
OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
endif

ifeq ("$(OSNAME)", "linux")
	SRC+=src/platform_linux.c
	CFLAGS+=-DPLATFORM_LINUX
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "openbsd")
	SRC+=src/platform_openbsd.c
	CFLAGS+=-DPLATFORM_OPENBSD
endif

all: $(BIN)

OBJS=	$(SRC:%.c=$(OBJDIR)/%.o)

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BIN)

.PHONY: all clean force
